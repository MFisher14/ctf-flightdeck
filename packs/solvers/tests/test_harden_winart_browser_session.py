"""Real LZ4 compressor and hand-built Mozilla/Chromium session semantics.

https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
https://chromium.googlesource.com/chromium/src/+/main/components/sessions/core/session_backend.cc
"""
import json
import random
import struct

import lz4.block
import pytest

import browser_session as engine


DOCUMENT = {'selectedWindow': 2, 'session': {'lastUpdate': 1577934245123}, 'windows': [
    {'selected': 1, 'tabs': [{'index': 1, 'entries': [{'url': 'https://first.invalid/'}]}]},
    {'selected': 1, 'tabs': [{'index': 2, 'entries': [{'url': 'https://old.invalid/'},
        {'url': 'https://active.invalid/', 'title': 'Active', 'referrer': 'https://old.invalid/'}]}],
     '_closedTabs': [{'state': {'index': 1, 'entries': [{'url': 'https://closed.invalid/'}]}}]}]}


def mozlz4():
    raw = json.dumps(DOCUMENT, separators=(',', ':')).encode()
    return b'mozLz40\0' + struct.pack('<I', len(raw)) + lz4.block.compress(raw, store_size=False), raw


def snss():
    url = b'https://fixture.invalid/'
    payload = struct.pack('<I', len(url)) + url
    payload += bytes((-len(url)) % 4)
    return b'SNSS' + struct.pack('<iH', 1, len(payload) + 1) + b'\x06' + payload


@pytest.mark.parametrize('payload', [b'', b'hello', b'abcdef' * 5000, bytes(range(256)) * 7])
def test_lz4_real_compressor_exact_output(payload):
    encoded = lz4.block.compress(payload, store_size=False)
    assert engine.lz4_block_decompress(encoded, expected_size=len(payload)) == payload


def test_mozilla_json_and_selected_window_semantics():
    encoded, raw = mozlz4()
    assert engine.detect(encoded) == 'mozlz4'
    assert engine.decode_mozlz4(encoded) == raw
    assert engine.read_firefox_session(encoded) == DOCUMENT
    out = engine.firefox_summary(DOCUMENT)
    assert out['active_url'] == 'https://active.invalid/'
    assert out['active_title'] == 'Active'
    assert out['windows'] == 2 and out['open_tabs'] == 2
    assert out['entries'] == 4
    assert out['session_last_update'] == 1577934245123
    assert len(engine.firefox_entries(DOCUMENT, include_closed=False)) == 3
    closed = engine.firefox_entries(DOCUMENT)[-1]
    assert closed['closed_tab'] is True and closed['is_current'] is False


def test_chromium_framing_and_independent_pickle_string():
    out = engine.read_snss(snss())
    assert engine.detect(snss()) == 'snss'
    assert (out['version'], out['commands'], out['command_ids'], out['complete']) == (1, 1, {6: 1}, True)
    leads = engine.snss_candidate_strings(out)
    assert leads == [{'command_index': 0, 'command_id': 6, 'offset': 0, 'encoding': 'utf-8',
                      'text': 'https://fixture.invalid/', 'url_like': True, 'proven': False}]
    cut = engine.read_snss(snss()[:-1])
    assert cut['complete'] is False and cut['commands'] == 0
    assert cut['trailing'] == snss()[8:-1]


def test_explicit_small_decompression_ceiling(monkeypatch):
    encoded = lz4.block.compress(b'x' * 4096, store_size=False)
    monkeypatch.setattr(engine, '_MAX_DECOMPRESSED', 32)
    with pytest.raises(engine.BrowserSessionError):
        engine.lz4_block_decompress(encoded)
    with pytest.raises(engine.BrowserSessionError):
        engine.decode_mozlz4(b'mozLz40\0' + struct.pack('<I', 4096) + encoded)


@pytest.mark.parametrize('entry', [engine.lz4_block_decompress, engine.decode_mozlz4,
    engine.read_firefox_session, engine.read_snss, engine.detect])
def test_bounded_deterministic_binary_fuzz(entry):
    rng = random.Random(0x5155)
    data = [b'', b'\xff' * 256] + [rng.randbytes(n) for n in (1, 8, 32, 512)]
    for valid in (mozlz4()[0], snss()):
        data += [valid[:n] for n in (1, 4, 7, 8, 11, len(valid)-1)]
        for _ in range(12):
            changed = bytearray(valid)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            data.append(bytes(changed))
    for raw in data:
        try:
            entry(raw)
        except engine.BrowserSessionError:
            pass


def test_lz4_invalid_terminal_match_rejected_by_reference():
    raw = b'\x10A\x01\x00'
    with pytest.raises(lz4.block.LZ4BlockError):
        lz4.block.decompress(raw, uncompressed_size=5)
    with pytest.raises(engine.BrowserSessionError):
        engine.lz4_block_decompress(raw, expected_size=5)


def test_zero_size_snss_command_keeps_trailing_bytes():
    assert engine.read_snss(b'SNSS\x01\0\0\0\0\0')['trailing'] == b'\0\0'


@pytest.mark.parametrize('entry', [engine.lz4_block_decompress, engine.decode_mozlz4,
                                  engine.read_firefox_session, engine.read_snss, engine.detect])
def test_wrong_type_only_declared_error(entry):
    try:
        entry(None)
    except engine.BrowserSessionError:
        pass


def test_nested_session_json_only_declared_error():
    try:
        engine.read_firefox_session(b'{"x":' + b'[' * 20000 + b'0' + b']' * 20000 + b'}')
    except engine.BrowserSessionError:
        pass


def test_malformed_tabs_only_declared_error():
    try:
        engine.firefox_summary({'windows': [{'tabs': 7}]})
    except engine.BrowserSessionError:
        pass


@pytest.mark.parametrize('args', [[], ['--help'], ['--invalid']])
def test_cli_guard(args):
    assert isinstance(engine.main(args), int)
