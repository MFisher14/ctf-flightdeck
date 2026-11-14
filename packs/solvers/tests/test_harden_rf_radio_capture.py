"""Independent Bluetooth/IEEE802.15.4 capture vectors; no radio is opened.

Oracles: Bluetooth Core ATT/LL layouts, Scapy Bluetooth4LE encoder,
classic pcap/btsnoop layouts, and cryptography AESCCM authenticated encryption.
https://github.com/secdev/scapy/blob/master/scapy/layers/bluetooth4LE.py
https://www.bluetooth.com/specifications/specs/core-specification-6-1/
"""
import random
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import pytest
from scapy.layers.bluetooth import EIR_Hdr, EIR_CompleteLocalName
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_SCAN_REQ, BTLE_RF

import radio_capture as radio


ATT = bytes.fromhex('1b3412') + b'CSCTF{att}'
L2 = struct.pack('<HH', len(ATT), 4) + ATT
ACL = struct.pack('<HH', 0x2345, len(L2)) + L2
H4 = b'\x02' + ACL
ZCL = bytes.fromhex('0434124200') + bytes.fromhex('00001000')
APS = bytes.fromhex('0001060004010244') + ZCL
NWK = bytes.fromhex('0800785634121e55') + APS
MAC = bytes.fromhex('418833efbe78563412') + NWK


def pcap(frame, linktype=230, endian='<'):
    return (struct.pack(endian + 'IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
            + struct.pack(endian + 'IIII', 1700000000, 123456, len(frame), len(frame)) + frame)


def snoop(frame=H4):
    return (b'btsnoop\0' + struct.pack('>II', 1, 1002)
            + struct.pack('>IIIIQ', len(frame), len(frame), 1, 0, 0xe03ab44a676000) + frame)


def ble_packet():
    return (BTLE() / BTLE_ADV() / BTLE_ADV_IND(AdvA='11:22:33:44:55:66')
            / EIR_Hdr() / EIR_CompleteLocalName(local_name=b'node'))


def test_ad_structure_fields_and_scanned_ble_oracle():
    fields = radio.parse_ad_structures(bytes.fromhex('02010603030d18020afc05ff4c004142'))
    assert fields[0]['flags'] == 6
    assert fields[1]['uuids'] == ['180d']
    assert fields[2]['dbm'] == -4
    assert fields[3]['company_id'] == 0x004c
    assert fields[3]['manufacturer_data'] == b'AB'
    out = radio.parse_ble_advertising(bytes(ble_packet())[4:-3])
    assert out['pdu_name'] == 'ADV_IND'
    assert out['advertiser'] == '11:22:33:44:55:66'
    assert out['advertising_data'][0]['text'] == 'node'


def test_ble_scan_request_address_roles():
    raw = bytes(BTLE_ADV(PDU_type=3) / BTLE_SCAN_REQ(ScanA='11:22:33:44:55:66', AdvA='aa:bb:cc:dd:ee:ff'))
    assert radio.parse_ble_advertising(raw)['advertiser'] == 'AA:BB:CC:DD:EE:FF'


@pytest.mark.parametrize('entry', [radio.parse_att, lambda raw: radio.parse_hci_acl(ACL)['l2cap']['att'],
                                  lambda raw: radio.parse_h4_stream(H4)[0]['l2cap']['att']])
def test_att_l2cap_hci_fields(entry):
    out = entry(ATT)
    assert out['handle'] == 0x1234
    assert out['operation'] == 'HandleValueNotification'
    assert out['value'] == b'CSCTF{att}'
    assert radio.parse_hci_acl(ACL)['handle'] == 0x345
    assert radio.parse_hci_acl(ACL)['packet_boundary'] == 2


def test_btsnoop_h4_command_event_and_timestamp():
    command = bytes.fromhex('01030c00')  # HCI Reset, OGF3 OCF3, zero parameters.
    event = bytes.fromhex('040e0401030c00')
    rows = radio.parse_h4_stream(command + event)
    assert rows[0]['opcode'] == 0x0c03
    assert (rows[0]['ogf'], rows[0]['ocf']) == (3, 3)
    assert rows[1]['event'] == 0x0e
    assert rows[1]['parameters'] == bytes.fromhex('01030c00')
    record = radio.parse_btsnoop(snoop())[0]
    assert record['timestamp'] == 0xe03ab44a676000
    assert record['flags'] == 1
    assert record['packets'][0]['l2cap']['att']['value'] == b'CSCTF{att}'


def test_ieee802154_zigbee_nested_fields():
    out = radio.parse_ieee802154(MAC)
    assert (out['sequence'], out['destination_pan'], out['source_pan']) == (0x33, '0xbeef', '0xbeef')
    assert (out['destination'], out['source']) == ('0x5678', '0x1234')
    nwk = radio.parse_zigbee_nwk(NWK)
    assert (nwk['destination'], nwk['source'], nwk['radius'], nwk['sequence']) == ('0x5678', '0x1234', 30, 0x55)
    aps = radio.parse_zigbee_aps(APS)
    assert (aps['cluster'], aps['profile'], aps['source_endpoint'], aps['destination_endpoint']) == (6, 0x104, 2, 1)
    zcl = radio.parse_zcl(ZCL)
    assert zcl['manufacturer_code'] == 0x1234
    assert zcl['transaction_sequence'] == 0x42
    assert zcl['attribute_ids'] == [0, 0x10]


def test_zigbee_aesccm_reference_and_authentication_failure():
    key = bytes(range(16))
    source = bytes.fromhex('0807060504030201')
    header = bytes.fromhex('0812785634121e55') + source
    aux = bytes.fromhex('2d04030201') + source + b'\x02'
    nonce = source + bytes.fromhex('040302012d')
    encrypted = AESCCM(key, tag_length=4).encrypt(nonce, APS, header + aux)
    out = radio.parse_zigbee_nwk(header + aux + encrypted, network_key=key)
    assert out['decryption']['verified'] is True
    assert out['nwk_payload'] == APS
    assert out['aps']['zcl']['attribute_ids'] == [0, 0x10]
    tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    out = radio.parse_zigbee_nwk(header + aux + tampered, network_key=key)
    assert out['decryption']['verified'] is False
    assert 'nwk_payload' not in out and 'aps' not in out


@pytest.mark.parametrize('endian', ['<', '>'])
def test_pcap_and_analyze_known_frame(endian):
    data = pcap(MAC, endian=endian)
    link, frames = radio.pcap_records(data)
    assert link == 230 and frames == [MAC]
    out = radio.analyze(data)
    assert out['offline'] is True
    assert out['records'][0]['source'] == '0x1234'


@pytest.mark.parametrize('linktype', [251, 256])
def test_ble_pcap_matches_scapy_linktype_envelope(linktype):
    packet = ble_packet()
    raw = bytes(packet if linktype == 251 else BTLE_RF() / packet)
    out = radio.analyze(pcap(raw, linktype))
    assert [row['advertiser'] for row in out['records']] == ['11:22:33:44:55:66']


def corpus():
    rng = random.Random(0x52414449)
    samples = [b'', b'\xff' * 257, b'\0' * 257, b'\xff' * 4096]
    samples.extend(rng.randbytes(n) for n in (1, 2, 4, 8, 16, 64, 256, 1024))
    for seed in (bytes(ble_packet())[4:-3], ATT, ACL, H4, ZCL, APS, NWK, MAC, pcap(MAC), snoop()):
        samples.extend(seed[:n] for n in range(len(seed)))
        for _ in range(12):
            data = bytearray(seed)
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            samples.append(bytes(data))
    return samples


PARSERS = [radio.parse_ad_structures, radio.parse_ble_advertising, radio.parse_att,
           radio.parse_hci_acl, radio.parse_h4_stream, radio.parse_btsnoop, radio.parse_ieee802154,
           radio.parse_zigbee_nwk, radio.parse_zigbee_aps, radio.parse_zcl, radio.pcap_records, radio.analyze]


@pytest.mark.parametrize('entry', PARSERS)
def test_saved_bytes_fuzz_only_declared_errors(entry):
    for raw in corpus():
        try:
            entry(raw)
        except radio.RadioError:
            pass


def test_explicit_small_file_packet_and_count_limits(monkeypatch):
    monkeypatch.setattr(radio, 'MAX_FILE', 16)
    with pytest.raises(radio.RadioError):
        radio.analyze(MAC)
    monkeypatch.setattr(radio, 'MAX_PACKET', 16)
    assert radio.parse_ieee802154(MAC) is None
    assert radio.parse_zigbee_nwk(NWK) is None
    with pytest.raises(radio.RadioError):
        radio.parse_btsnoop(snoop())
    with pytest.raises(radio.RadioError):
        radio.pcap_records(pcap(MAC))
    monkeypatch.setattr(radio, 'MAX_PACKETS', 1)
    with pytest.raises(radio.RadioError):
        radio.parse_h4_stream(bytes.fromhex('01030c0001030c00'))


@pytest.mark.parametrize('entry', [radio.parse_hci_acl, radio.parse_h4_stream, radio.parse_btsnoop,
                                 radio.parse_zcl, radio.pcap_records])
def test_none_input_declines_without_stdlib_exception(entry):
    try:
        entry(None)
    except radio.RadioError:
        pass


def test_cli_help_returns_status(capsys):
    assert radio.main(['--help']) == 0


def test_cli_valid_offline_capture(tmp_path, capsys):
    path = tmp_path / 'fixture.pcap'
    path.write_bytes(pcap(MAC))
    assert radio.main([str(path), '--json']) == 0
    assert '"source": "0x1234"' in capsys.readouterr().out
