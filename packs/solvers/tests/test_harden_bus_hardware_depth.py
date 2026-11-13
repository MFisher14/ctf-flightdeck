"""Hardware vectors from datasheet bus semantics and independent cantools DBC.

References: Winbond W25Q64JV command table (03/0B/02/9F/B7/E9),
Microchip 24LC256 random-read sequence, ARM ADIv5 DPIDR/IEEE1149.1 IDCODE.
This legacy module explicitly uses ValueError as its input-error contract.
"""
import random
import struct
import zlib

import cantools
import pytest

import hardware_depth as hw


DBC = '''VERSION ""
NS_ :
BS_:
BU_: ECU
BO_ 291 Msg: 8 ECU
 SG_ Little : 0|16@1+ (0.5,-10) [0|32757] "V" ECU
 SG_ Big : 23|12@0- (1,0) [-2048|2047] "" ECU
 SG_ Mux M : 32|8@1+ (1,0) [0|255] "" ECU
 SG_ Branch m2 : 40|8@1+ (1,0) [0|255] "" ECU
'''
VALUES = {'Little': 100.5, 'Big': -123, 'Mux': 2, 'Branch': 77}
BAD_CSV_RANDOM = 'a!e\x18#8u\r+\x07|W\x17p\x072;hA\x17R?4\x11\x01-_\x14n\x1f'


def spi_csv(mosi, miso):
    samples = [(0, 0, 0, 1), (0, 0, 0, 0)]
    for left, right in zip(mosi, miso):
        for shift in range(7, -1, -1):
            out, inp = (left >> shift) & 1, (right >> shift) & 1
            samples.extend([(0, out, inp, 0), (1, out, inp, 0), (0, out, inp, 0)])
    samples.append((0, 0, 0, 1))
    return 'clk,mosi,miso,cs\n' + '\n'.join(','.join(map(str, row)) for row in samples)


def i2c_csv():
    samples = [(1, 1), (1, 0)]
    def byte(value, ack=0):
        for bit in [(value >> shift) & 1 for shift in range(7, -1, -1)] + [ack]:
            samples.extend([(0, bit), (1, bit), (0, bit)])
    for value in [0xa0, 0x01, 0x20]:
        byte(value)
    # Repeated START: SDA is released while SCL low, then falls while SCL high.
    samples.extend([(0, 1), (1, 1), (1, 0)])
    byte(0xa1)
    byte(0xde)
    byte(0xad, ack=1)
    samples.extend([(0, 0), (1, 0), (1, 1)])
    return 'scl,sda\n' + '\n'.join(f'{scl},{sda}' for scl, sda in samples)


def test_spi_command_address_dummy_clock_and_sparse_image():
    out = hw.decode_spi_flash([
        {'mosi': '9f000000', 'miso': '00ef4017'},
        {'mosi': '030001200000', 'miso': '000000004142'},
        {'mosi': '0b000124000000', 'miso': '00000000004344'},
        {'mosi': '0200012258'},
    ])
    assert out['jedec_ids'] == [bytes.fromhex('ef4017')]
    assert (out['base'], out['end'], out['known'], out['holes']) == (0x120, 0x126, 5, 1)
    assert out['image'] == b'ABX\xffCD'
    assert [row['name'] for row in out['operations']] == ['read-jedec-id', 'read', 'fast-read', 'page-program']
    assert out['operations'][2]['address'] == 0x124


def test_spi_4byte_mode_and_truncated_transaction():
    out = hw.decode_spi_flash([
        {'mosi': b'\xb7'}, {'mosi': bytes.fromhex('030100002000'), 'miso': b'\0' * 5 + b'X'},
        {'mosi': b'\xe9'}, {'mosi': bytes.fromhex('0300')},
    ])
    assert out['base'] == 0x01000020 and out['image'] == b'X'
    assert out['operations'][-1]['truncated'] is True


def test_spi_logic_capture_full_pipeline():
    capture = spi_csv(bytes.fromhex('030001200000'), bytes.fromhex('000000004142'))
    out = hw.decode_logic_trace(capture)
    assert out['spi_transactions'] == [{'mosi': bytes.fromhex('030001200000'),
                                         'miso': bytes.fromhex('000000004142'), 'complete': True}]
    assert out['spi_flash']['base'] == 0x120
    assert out['spi_flash']['image'] == b'AB'


def test_i2c_pointer_write_repeated_start_and_nack():
    out = hw.decode_logic_trace(i2c_csv())
    assert out['i2c'] == [
        {'address': 0x50, 'rw': 'w', 'data': b'\x01\x20', 'acks': [True, True, True]},
        {'address': 0x50, 'rw': 'r', 'data': b'\xde\xad', 'acks': [True, True, False]},
    ]
    assert out['i2c_eeprom']['base'] == 0x120
    assert out['i2c_eeprom']['image'] == b'\xde\xad'
    again = hw.reconstruct_i2c_eeprom([
        {'address': 0x50, 'rw': 'w', 'data': b'\x01\x20'},
        {'address': 0x50, 'rw': 'r', 'data': b'AB'},
        {'address': 0x50, 'rw': 'r', 'data': b'CD'},
    ])
    assert again['image'] == b'ABCD'
    assert [row['address'] for row in again['operations']] == [0x120, 0x120, 0x122]


def test_dbc_cantools_endianness_signed_scale_and_mux():
    oracle = cantools.database.load_string(DBC, 'dbc')
    data = oracle.encode_message(291, VALUES)
    assert data.hex() == 'dd00f850024d0000'
    database = hw.parse_dbc(DBC)
    assert (database['message_count'], database['signal_count']) == (1, 4)
    result = hw.decode_dbc_frame(database, 291, data)
    assert {row['name']: row['value'] for row in result['signals']} == oracle.decode_message(291, data) == VALUES
    assert {row['name']: row['raw'] for row in result['signals']} == {'Little': 221, 'Big': -123, 'Mux': 2, 'Branch': 77}
    assert hw.decode_dbc_frame(database, 291, data[:-1]) is None
    assert hw.decode_dbc_frame(database, 292, data) is None
    log = '\n'.join(f'({time:.6f}) can0 123#{data.hex()}' for time in [1.0, 1.25, 1.5])
    decoded = hw.decode_can_log_with_dbc(log, DBC)
    assert len(decoded) == 3
    assert [row['timestamp'] for row in decoded] == [1.0, 1.25, 1.5]
    assert all({signal['name']: signal['value'] for signal in row['signals']} == VALUES for row in decoded)


def test_extended_dbc_frame_id_cantools_oracle():
    dbc = DBC.replace('BO_ 291 ', 'BO_ 2147490492 ')
    oracle = cantools.database.load_string(dbc, 'dbc')
    assert oracle.messages[0].frame_id == 0x1abc
    data = oracle.encode_message(0x1abc, VALUES)
    result = hw.decode_dbc_frame(hw.parse_dbc(dbc), 0x1abc, data)
    assert result is not None


def test_debug_idcode_and_uart_variables():
    assert hw.boundary_scan_notes('jtag', 0x4ba00477)['identifier'] == {
        'raw': 0x4ba00477, 'version': 4, 'part': 0xba00, 'manufacturer': 0x23b, 'idcode_lsb_valid': True}
    assert hw.boundary_scan_notes('swd', 0x2ba01477)['identifier'] == {
        'raw': 0x2ba01477, 'revision': 2, 'part': 0xba, 'designer': 0x23b, 'dpidr_lsb_valid': True}
    out = hw.classify_uart_bootloader(b'U-Boot 2024.01\nbootargs=console=ttyS0\nflag=CSCTF{uart}\n')
    assert out['candidates'][0]['family'] == 'u-boot'
    assert out['bootargs'] == 'console=ttyS0'
    assert out['variables']['flag'] == 'CSCTF{uart}'


def test_firmware_environment_crc_reference():
    body = b'bootcmd=bootm\0flag=CSCTF{env}\0\0'.ljust(4092, b'\xff')
    blob = b'\0' * 4096 + struct.pack('<I', zlib.crc32(body)) + body
    out = hw.carve_firmware(blob)
    assert len(out) == 1
    assert (out[0]['offset'], out[0]['kind']) == (4096, 'uboot_env')
    assert out[0]['report']['vars']['flag'] == 'CSCTF{env}'


@pytest.mark.parametrize('function', [hw.decode_spi_flash, hw.reconstruct_i2c_eeprom])
def test_transaction_fuzz_and_small_caps(function, monkeypatch):
    rng = random.Random(0xb055)
    for count in range(32):
        raw = rng.randbytes(count)
        for value in [None, [], [None], [{'mosi': raw, 'miso': raw, 'address': 0x50, 'rw': 'w', 'data': raw}],
                      [{'mosi': b'\xff' * count, 'data': b'\xff' * count}]]:
            try:
                function(value)
            except ValueError:
                pass
    monkeypatch.setattr(hw, 'MAX_TRANSACTIONS', 2)
    with pytest.raises(ValueError):
        function([{}, {}, {}])


@pytest.mark.parametrize('function', [hw.parse_dbc, hw.decode_logic_trace, hw.classify_uart_bootloader])
def test_text_fuzz_random_truncations_mutations(function):
    rng = random.Random(404)
    samples = ['', '\xff' * 128, '0' * 1024]
    samples += [''.join(chr(rng.randrange(128)) for _ in range(n)) for n in range(32)]
    samples += [DBC[:n] for n in range(0, len(DBC), 13)]
    for text in samples:
        if function is hw.decode_logic_trace and text == BAD_CSV_RANDOM:
            continue  # The exact discovered mutation is isolated below.
        try:
            function(text)
        except ValueError:
            pass


def test_explicit_image_and_firmware_caps(monkeypatch):
    monkeypatch.setattr(hw, 'MAX_IMAGE_SPAN', 8)
    with pytest.raises(ValueError):
        hw.decode_spi_flash([{'mosi': b'\x02\0\0\0' + b'A' * 9}])
    with pytest.raises(ValueError):
        hw.reconstruct_i2c_eeprom([{'address': 0x50, 'rw': 'w', 'data': b'\0\0' + b'A' * 9}])
    monkeypatch.setattr(hw, 'MAX_INPUT', 8)
    with pytest.raises(ValueError):
        hw.carve_firmware(b'\0' * 9)
    monkeypatch.setattr(hw, 'MAX_DBC_SIGNALS', 2)
    with pytest.raises(ValueError):
        hw.parse_dbc(DBC)


def test_malformed_database_container_only_contract_error():
    try:
        hw.decode_dbc_frame({'messages': [{}]}, 1, b'')
    except ValueError:
        pass


def test_malformed_signal_only_contract_error():
    try:
        hw.decode_dbc_frame({'messages': {1: {'length': 1, 'signals': [{}]}}}, 1, b'\0')
    except ValueError:
        pass


def test_oversized_csv_field_only_contract_error():
    try:
        hw.decode_logic_trace('clk,mosi\n' + 'A' * 140000)
    except ValueError:
        pass


def test_random_csv_carriage_return_only_contract_error():
    try:
        hw.decode_logic_trace(BAD_CSV_RANDOM)
    except ValueError:
        pass
