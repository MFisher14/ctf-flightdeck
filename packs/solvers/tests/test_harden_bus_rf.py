"""Independent digital captures for rf's legacy UART/SPI-mode0/I2C decoders.

Sources: NXP UM10204 https://www.nxp.com/docs/en/user-guide/UM10204.pdf
and TI SPI modes https://www.ti.com/document-viewer/lit/html/SBOA621
UART 8N1 is a low start, eight LSB-first data bits, then a high stop.
This module deliberately tests only rf's documented 7-bit I2C/mode0 SPI.
"""
import random

import numpy as np
import pytest

import rf as engine


def uart_capture(payload, samples_per_bit=10):
    levels = [1] * samples_per_bit
    for byte in payload:
        for bit in [0] + [(byte >> i) & 1 for i in range(8)] + [1]:
            levels.extend([bit] * samples_per_bit)
    return levels + [1] * samples_per_bit


def spi_capture(messages):
    clk, mosi, miso, cs = [0], [0], [0], [1]
    for outgoing, incoming in messages:
        for left, right in zip(outgoing, incoming):
            for bit in range(7, -1, -1):
                for clock in (0, 1, 0):
                    clk.append(clock); mosi.append((left >> bit) & 1)
                    miso.append((right >> bit) & 1); cs.append(0)
        clk.append(0); mosi.append(0); miso.append(0); cs.append(1)
    return clk, mosi, miso, cs


def i2c_capture():
    samples = [(1, 1)]
    def start():
        samples.extend([(0, 1), (1, 1), (1, 0), (0, 0)])
    def octet(value, acknowledged=True):
        for bit in [(value >> i) & 1 for i in range(7, -1, -1)] + [int(not acknowledged)]:
            samples.extend([(0, bit), (1, bit), (0, bit)])
    start(); octet(0xa0); octet(0x10)
    start(); octet(0xa1); octet(0x5a, False)
    samples.extend([(0, 0), (1, 0), (1, 1)])
    return [a for a, _ in samples], [b for _, b in samples]


def test_uart_8n1_baud_lsb_and_inversion():
    levels = uart_capture(b'\x55\xa3\x00\xff')
    times = [i / 96000 for i in range(len(levels))]
    for capture, inverse in ((levels, False), ([1 - bit for bit in levels], True)):
        result = engine.uart_decode(capture, time=times, baud=9600, inverted=inverse)
        assert result['bytes'] == b'\x55\xa3\x00\xff'
        assert result['framing_errors'] == 0
        assert result['baud'] == 9600
        assert result['bit_time'] == pytest.approx(1 / 9600)


def test_mode0_full_duplex_and_chip_select_boundaries():
    channels = spi_capture([(b'\x9f\x00\x00', b'\x00\xef\x40'), (b'\x06', b'\xff')])
    assert engine.spi_decode(*channels) == {'mosi': b'\x9f\0\0\x06', 'miso': b'\0\xef\x40\xff'}
    assert engine.spi_transactions(*channels) == [
        {'mosi': b'\x9f\0\0', 'miso': b'\0\xef\x40', 'complete': True},
        {'mosi': b'\x06', 'miso': b'\xff', 'complete': True}]
    assert engine.spi_transactions(*channels, max_transactions=1) == [
        {'mosi': b'\x9f\0\0', 'miso': b'\0\xef\x40', 'complete': True}]


def test_i2c_repeated_start_seven_bit_address_ack_nack():
    assert engine.i2c_decode(*i2c_capture()) == [
        {'address': 0x50, 'rw': 'w', 'data': b'\x10', 'acks': [True, True]},
        {'address': 0x50, 'rw': 'r', 'data': b'\x5a', 'acks': [True, False]}]


def test_csv_explicit_microsecond_column():
    result = engine.logic_csv('time_us,rx\n0,1\n10,0\n20,1\n')
    assert result['time'] == pytest.approx([0, 1e-5, 2e-5])
    assert result['columns'] == {'rx': [1, 0, 1]}


def test_csv_bracketed_microseconds_are_seconds():
    result = engine.logic_csv('Time [us],rx\n0,1\n10,0\n20,1\n')
    assert result['time'] == pytest.approx([0, 1e-5, 2e-5])


def test_finite_binary_capture_fuzz():
    rng = random.Random(0x627573)
    for length in (1, 2, 7, 16, 31, 100, 513):
        clk = [rng.randrange(2) for _ in range(length)]
        data = [rng.randrange(2) for _ in range(length)]
        assert isinstance(engine.i2c_decode(clk, data), list)
        assert isinstance(engine.spi_decode(clk, data), dict)
        assert isinstance(engine.spi_transactions(clk, data), list)
        assert engine.uart_decode(data) is None or isinstance(engine.uart_decode(data), dict)
    assert engine.uart_decode([]) is None
    assert engine.spi_transactions([], []) == []
    assert engine.spi_transactions([0, 1], []) == []


@pytest.mark.parametrize('call', [lambda: engine.i2c_decode([], []), lambda: engine.spi_decode([]),
                                 lambda: engine.spi_decode([0, 1], mosi=[])])
def test_empty_or_ragged_capture_fails_closed(call):
    call()


def test_uart_accepts_sampled_numpy_time_axis():
    levels = uart_capture(b'U')
    result = engine.uart_decode(levels, time=np.arange(len(levels)) / 96000, baud=9600)
    assert result['bytes'] == b'U'


@pytest.mark.parametrize('raw', ['', '\xff' * 20, 'a,b\n1\n', 'a,b\n1,wat\n0,1\n0,1\n'])
def test_malformed_csv_declines(raw):
    assert engine.logic_csv(raw) is None
