"""Independent saved digital captures: UART, four SPI modes, I2C, TAP and SWD.

References: NXP UM10204 (I2C including ten-bit read repeated START), TI
SBOA621 (SPI sampling edges), IEEE1149.1 TAP state machine, and ARM ADI
IHI0031 (SWD request/ACK/parity/turnaround fields).
https://www.nxp.com/docs/en/user-guide/UM10204.pdf
https://www.ti.com/document-viewer/lit/html/SBOA621
https://developer.arm.com/documentation/ihi0031/latest/
"""
import random

import pytest

import logic_faults as engine


def uart(payload, parity='none', inverted=False):
    stream = [1] * 8
    for value in payload:
        bits = [0] + [(value >> i) & 1 for i in range(8)]
        if parity != 'none':
            bits.append((value.bit_count() & 1) ^ (parity == 'odd'))
        bits += [1]
        for bit in bits:
            stream.extend([int(bit)] * 8)
    stream += [1] * 8
    return [int(bit) ^ inverted for bit in stream]


def spi(mode, payload, received, order='msb'):
    idle, phase = mode >> 1, mode & 1
    rows = [(idle, 0, 0, 1), (idle, 0, 0, 0)]
    for left, right in zip(payload, received):
        for bit in (range(7, -1, -1) if order == 'msb' else range(8)):
            a, b = (left >> bit) & 1, (right >> bit) & 1
            if phase == 0:
                rows.extend([(idle, a, b, 0), (1-idle, a, b, 0), (idle, 1-a, 1-b, 0)])
            else:
                rows.extend([(1-idle, 1-a, 1-b, 0), (1-idle, a, b, 0), (idle, a, b, 0)])
    rows.append((idle, 0, 0, 1))
    return [[row[i] for row in rows] for i in range(4)]


class I2C:
    def __init__(self):
        self.rows = [(1, 1)]
    def start(self):
        self.rows += [(0, 1), (1, 1), (1, 0), (0, 0)]
    def byte(self, value, ack=True):
        for bit in [(value >> i) & 1 for i in range(7, -1, -1)] + [int(not ack)]:
            self.rows += [(0, bit), (1, bit), (0, bit)]
    def stop(self):
        self.rows += [(0, 0), (1, 0), (1, 1)]
    def channels(self):
        return [a for a, b in self.rows], [b for a, b in self.rows]


def swd_request(ap, read, address, value=None, ack=1, bad_parity=False):
    fields = [ap, read, (address >> 2) & 1, (address >> 3) & 1]
    bits = [1] + fields + [sum(fields) & 1, 0, 1] + [0]
    bits += [(ack >> i) & 1 for i in range(3)]
    if ack == 1:
        if not read:
            bits += [0]
        bits += [(value >> i) & 1 for i in range(32)]
        bits += [(value.bit_count() & 1) ^ bad_parity]
    return ''.join(str(int(bit)) for bit in bits)


@pytest.mark.parametrize('parity', ['none', 'even', 'odd'])
@pytest.mark.parametrize('inverted', [False, True])
def test_uart_lsb_baud_parity_and_inversion(parity, inverted):
    signal = uart(b'\x55\xa3\x00\xff', parity, inverted)
    result = engine.decode_uart(signal, 76800, 9600, parity=parity, inverted=inverted)
    assert [row['value'] for row in result] == [0x55, 0xa3, 0, 255]
    assert all(row['framing_ok'] for row in result)
    assert all(row['parity_ok'] is (None if parity == 'none' else True) for row in result)
    assert engine.estimate_uart_baud(signal, 76800) == 9600


@pytest.mark.parametrize('mode', range(4))
@pytest.mark.parametrize('order', ['msb', 'lsb'])
def test_spi_all_four_modes_and_both_bit_orders(mode, order):
    clk, mosi, miso, cs = spi(mode, b'\xa3\x55', b'\x96\xf0', order)
    rows = engine.decode_spi(clk, mosi=mosi, miso=miso, cs=cs, mode=mode, bit_order=order)
    assert len(rows) == 1
    assert rows[0]['mosi'] == b'\xa3\x55'
    assert rows[0]['miso'] == b'\x96\xf0'
    assert rows[0]['complete'] is True


def test_i2c_seven_bit_repeated_start_and_ack():
    bus = I2C(); bus.start(); bus.byte(0xa0); bus.byte(0x10)
    bus.start(); bus.byte(0xa1); bus.byte(0x5a, False); bus.stop()
    rows = engine.decode_i2c(*bus.channels())
    assert [(r['address'], r['rw'], r['data'], r['acks']) for r in rows] == [
        (0x50, 'w', b'\x10', [True, True]), (0x50, 'r', b'\x5a', [True, False])]
    assert [row['repeated_start'] for row in rows] == [False, True]
    assert [row['stopped'] for row in rows] == [False, True]


def test_i2c_ten_bit_write():
    bus = I2C(); bus.start(); bus.byte(0xf4); bus.byte(0xaa); bus.byte(0x33); bus.stop()
    result = engine.decode_i2c(*bus.channels())[0]
    assert (result['address_bits'], result['address'], result['rw'], result['data']) == (10, 0x2aa, 'w', b'\x33')


def test_i2c_ten_bit_combined_read_preserves_prior_address():
    bus = I2C(); bus.start(); bus.byte(0xf4); bus.byte(0xaa)
    bus.start(); bus.byte(0xf5); bus.byte(0x55, False); bus.stop()
    result = engine.decode_i2c(*bus.channels())[1]
    assert (result['address_bits'], result['address'], result['rw'], result['data']) == (10, 0x2aa, 'r', b'\x55')


@pytest.mark.parametrize('kind', ['DR', 'IR'])
def test_jtag_tap_shift_lsb_first(kind):
    # Reset->idle->selectDR->(selectIR)->capture->shift; last data clock exits.
    controls = [0, 1] + ([1] if kind == 'IR' else []) + [0, 0]
    cycles = [(tms, 0, 0) for tms in controls]
    cycles += [(int(bit == 7), (0xa5 >> bit) & 1, (0x3c >> bit) & 1) for bit in range(8)]
    cycles += [(1, 0, 0), (0, 0, 0)]
    rows = [(0, 0, 0, 0)]
    for tms, tdi, tdo in cycles:
        rows += [(0, tms, tdi, tdo), (1, tms, tdi, tdo), (0, tms, tdi, tdo)]
    result = engine.decode_jtag(*[[r[i] for r in rows] for i in range(4)])
    assert result['final_state'] == 'run-test-idle'
    assert len(result['scans']) == 1
    scan = result['scans'][0]
    assert (scan['kind'], scan['tdi_value'], scan['tdo_value'], scan['complete']) == (kind, 0xa5, 0x3c, True)


@pytest.mark.parametrize(('ap', 'read', 'address', 'value'), [(0, 1, 0, 0x2ba01477), (1, 0, 12, 0xdeadbeef)])
def test_swd_requests_ack_and_data_parity(ap, read, address, value):
    result = engine.decode_swd_bits(swd_request(ap, read, address, value))[0]
    assert result['port'] == ('AP' if ap else 'DP')
    assert result['operation'] == ('read' if read else 'write')
    assert result['address'] == address
    assert result['ack'] == 'OK'
    assert result['data'] == value
    assert result['data_parity_ok'] is True
    bad = engine.decode_swd_bits(swd_request(ap, read, address, value, bad_parity=True))[0]
    assert bad['data_parity_ok'] is False


@pytest.mark.parametrize(('ack', 'name'), [(2, 'WAIT'), (4, 'FAULT')])
def test_swd_non_ok_ack(ack, name):
    result = engine.decode_swd_bits(swd_request(0, 1, 0, ack=ack))[0]
    assert result['ack'] == name
    assert 'data' not in result


def test_csv_logic_values_and_times():
    result = engine.parse_logic_csv('time,clk,data\n0,low,high\n0.001,1,false\n')
    assert result == {'time': [0, 0.001], 'channels': {'clk': [0, 1], 'data': [1, 0]}, 'sample_count': 2}


def test_random_truncated_bitflipped_and_small_caps(monkeypatch):
    rng = random.Random(0x535744)
    valid = swd_request(0, 1, 0, 0x2ba01477)
    streams = ['', '1' * 60] + [valid[:n] for n in range(len(valid))]
    for _ in range(20):
        changed = list(valid); index = rng.randrange(len(changed)); changed[index] = str(1-int(changed[index]))
        streams.append(''.join(changed))
    for text in streams:
        assert isinstance(engine.decode_swd_bits(text), list)
    for n in (0, 1, 2, 7, 64, 129):
        a, b = [[rng.randrange(2) for _ in range(n)] for _ in range(2)]
        assert isinstance(engine.decode_uart(a, 76800, 9600), list)
        assert isinstance(engine.decode_spi(a, mosi=b), list)
        assert isinstance(engine.decode_i2c(a, b), list)
        assert isinstance(engine.decode_jtag(a, b, a), dict)
    monkeypatch.setattr(engine, 'MAX_SAMPLES', 8)
    for call in (lambda: engine.decode_uart([0]*9, 76800, 9600),
                 lambda: engine.decode_spi([0]*9), lambda: engine.decode_i2c([0]*9, [0]*9),
                 lambda: engine.decode_jtag([0]*9, [0]*9, [0]*9),
                 lambda: engine.decode_swd_bits('0'*9)):
        with pytest.raises(engine.CaptureError):
            call()


@pytest.mark.parametrize('text', ['', 'time,a\n0,nope\n', 'time,a\nnan,1\n', 'time,a\n1,1\n0,0\n'])
def test_bad_csv_declared_error(text):
    with pytest.raises(engine.CaptureError):
        engine.parse_logic_csv(text)


def test_absent_or_unequal_channels_raise_declared_error():
    with pytest.raises(engine.CaptureError):
        engine.decode_spi(None)
    with pytest.raises(engine.CaptureError):
        engine.decode_i2c([0, 1], [0])


@pytest.mark.parametrize('call', [
    lambda: engine.parse_logic_csv('\ud800'),
    lambda: engine.decode_uart(None, 76800, 9600),
    lambda: engine.decode_uart([1, 0], 76800, 9600, parity=None),
    lambda: engine.decode_swd_bits('0', turnaround=None),
])
def test_malformed_types_only_declared_errors(call):
    try:
        call()
    except engine.CaptureError:
        pass


@pytest.mark.parametrize('argv', [[], ['--help'], ['--unknown']])
def test_cli_parser_guard(argv):
    assert isinstance(engine.main(argv), int)
