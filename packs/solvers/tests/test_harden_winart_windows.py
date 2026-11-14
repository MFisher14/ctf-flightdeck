"""Independent MS-SHLLINK/FILETIME, registry, EVTX and USN fixtures.

References: Microsoft MS-SHLLINK ShellLinkHeader and TrackerDataBlock;
FILETIME and USN_RECORD_V2 documentation; libyal EVTX format; regipy.
"""
from datetime import datetime, timezone
import io
import json
import os
import random
import socket
import struct
import subprocess
import urllib.request
import uuid

import pytest
from regipy.registry import RegistryHive

import windows as win


EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
DATE = datetime(2020, 2, 29, 12, 34, 56, tzinfo=timezone.utc)
TICKS = ((DATE - EPOCH).days * 86400 + (DATE - EPOCH).seconds) * 10_000_000 + 1234567
CLSID = uuid.UUID('00021401-0000-0000-c000-000000000046').bytes_le


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    calls = []
    def blocked(*args, **kwargs):
        calls.append('execution/network')
        raise AssertionError('static analysis attempted execution/network')
    for obj, names in [(os, ['system', 'popen']), (subprocess, ['Popen', 'run', 'call']),
                       (socket, ['create_connection']), (urllib.request, ['urlopen'])]:
        for name in names:
            monkeypatch.setattr(obj, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setenv('CTF_EVTX', 'python')
    monkeypatch.setattr(win, '_EVTX_RS', [None])
    yield
    assert calls == []


def closed(fn, value):
    try:
        return fn(value)
    except ValueError as exc:
        assert type(exc) is ValueError, f'leaked {type(exc).__name__}: {exc}'
        return None


def lnk_fixture(description='CSCTF{shortcut}', tracker=True):
    # LinkFlags: HasName, HasRelativePath, HasWorkingDir, HasArguments, IsUnicode.
    header = bytearray(76)
    struct.pack_into('<I', header, 0, 76)
    header[4:20] = CLSID
    struct.pack_into('<IIQQQIiI', header, 20, 0xBC, 0x20, TICKS, TICKS + 1,
                     TICKS + 2, 12345, -2, 3)
    body = bytearray(header)
    for text in [description, r'.\fixture.exe', r'C:\work', '--offline']:
        raw = text.encode('utf-16-le')
        body.extend(struct.pack('<H', len(raw) // 2) + raw)
    if tracker:
        block = bytearray(96)
        struct.pack_into('<IIII', block, 0, 96, 0xA0000003, 0x58, 0)
        block[16:23] = b'LABHOST'
        # MS mixed-endian GUID: UUID node 00:11:22:33:44:55 in version 1 GUID.
        block[48:64] = uuid.UUID('00112233-4455-1677-8899-001122334455').bytes_le
        body.extend(block)
    return bytes(body) + b'\0' * 4


def evtx_fixture():
    # Header/chunk/record envelopes; no fabricated BinXML payload is rendered.
    data = bytearray(0x11000)
    data[:8] = b'ElfFile\0'
    data[0x1000:0x1008] = b'ElfChnk\0'
    struct.pack_into('<I', data, 0x1030, 0x238)
    for offset, record, stamp in [(0x1200, 42, TICKS), (0x121c, 43, TICKS + 1)]:
        struct.pack_into('<IIQQI', data, offset, 0x2A2A, 28, record, stamp, 28)
    return bytes(data)


def hive_fixture():
    # Hand-built regf with one allocated nk root and one inline REG_DWORD vk.
    data = bytearray(8192)
    data[:4] = b'regf'
    struct.pack_into('<IIQIIIIIII', data, 4, 1, 1, TICKS, 1, 5, 0, 1, 0x20, 4096, 1)
    data[0x30:0x30+12] = 'SYSTEM'.encode('utf-16-le')
    data[4096:4100] = b'hbin'
    struct.pack_into('<II', data, 4100, 0, 4096)
    # Root cell occupies 88 bytes: 4 cell size + 76 nk + ROOT + padding.
    struct.pack_into('<i', data, 0x1020, -88)
    root = 0x1024
    data[root:root+2] = b'nk'
    struct.pack_into('<HQ', data, root+2, 0x24, TICKS)
    struct.pack_into('<I', data, root+0x10, 0xFFFFFFFF)
    struct.pack_into('<II', data, root+0x24, 1, 0x78)
    struct.pack_into('<HH', data, root+0x48, 4, 0)
    data[root+0x4C:root+0x50] = b'ROOT'
    struct.pack_into('<iI', data, 0x1078, -8, 0x80)
    struct.pack_into('<i', data, 0x1080, -32)
    vk = 0x1084
    data[vk:vk+2] = b'vk'
    struct.pack_into('<HIIIHH', data, vk+2, 5, 0x80000004, 0x12345678, 4, 1, 0)
    data[vk+20:vk+25] = b'Count'
    struct.pack_into('<i', data, 0x10A0, 4096-0xA0)
    checksum = 0
    for offset in range(0, 0x1fc, 4):
        checksum ^= struct.unpack_from('<I', data, offset)[0]
    struct.pack_into('<I', data, 0x1fc, checksum)
    return bytes(data)


def test_filetime_exact_100ns_and_timezone_conversion():
    stamp = win.filetime(TICKS)
    assert int(stamp) == TICKS
    assert stamp.iso() == '2020-02-29T12:34:56.1234567Z'
    assert int(win.parse_time('2020-02-29T14:34:56.1234567+02:00')) == TICKS
    assert int(win.from_unix(0)) == (datetime(1970, 1, 1, tzinfo=timezone.utc) - EPOCH).days * 86400 * 10_000_000
    assert win.parse_time('2020-02-29T12:34:56', assume_utc=False) is None
    assert win.filetime(0) is None
    assert win.filetime(1 << 64) is None


def test_lnk_header_stringdata_and_guid_node():
    out = win.lnk(lnk_fixture())
    assert (out['description'], out['relative_path'], out['working_dir'], out['arguments']) == (
        'CSCTF{shortcut}', r'.\fixture.exe', r'C:\work', '--offline')
    assert [int(out[key]) for key in ['creation_time', 'access_time', 'write_time']] == [TICKS, TICKS+1, TICKS+2]
    assert (out['file_size'], out['icon_index'], out['show_command']) == (12345, -2, 'maximized')
    assert (out['machine_id'], out['mac_address']) == ('LABHOST', '00:11:22:33:44:55')


def test_registry_binary_inline_dword_matches_regipy(tmp_path):
    data = hive_fixture()
    path = tmp_path / 'SYSTEM'; path.write_bytes(data)
    oracle = RegistryHive(str(path))
    assert oracle.root.get_value('Count') == 0x12345678
    parsed = win.open_registry(data)
    assert parsed.root.name == oracle.root.name == 'ROOT'
    assert parsed.root.values()['Count'].data == oracle.root.get_value('Count')
    assert int(parsed.root.ts) == TICKS


def test_registry_text_dword_qword_multisz_and_sid_path():
    text = ('Windows Registry Editor Version 5.00\r\n'
            '[HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Fixture]\r\n'
            '"Count"=dword:12345678\r\n'
            '"Wide"=hex(b):08,07,06,05,04,03,02,01\r\n'
            '"Multi"=hex(7):61,00,00,00,62,00,00,00,00,00\r\n')
    view = win.open_registry(b'\xff\xfe' + text.encode('utf-16-le'))
    key = next(key for key in view.walk() if key.name == 'Fixture')
    assert 'S-1-5-21-1-2-3-1001' in key.path
    values = key.values()
    assert values['Count'].data == 0x12345678
    assert values['Wide'].data == 0x0102030405060708
    assert values['Multi'].data == ['a', 'b']


def test_evtx_record_envelope_counts_and_exact_timestamps():
    data = evtx_fixture()
    assert win.evtx_chunks(data) == [0x1000]
    assert win.evtx_record_count(data) == 2
    assert win.evtx_header_times(data) == {42: TICKS, 43: TICKS+1}
    assert win.evtx_cut(data) is False
    assert win.evtx_cut(data[:-8]) is True


def test_event_xml_sid_guid_and_duplicate_fields():
    data = b'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>42</EventRecordID>
    <TimeCreated SystemTime="2020-02-29T12:34:56.1234567Z"/>
    <Security UserID="S-1-5-18"/><Execution ProcessID="1234"/></System><EventData>
    <Data Name="ProcessGuid">{00112233-4455-6677-8899-aabbccddeeff}</Data>
    <Data Name="Image">first.exe</Data><Data Name="Image">second.exe</Data></EventData></Event>'''
    rows, complete = win.xml_events(data, 'fixture.xml')
    assert complete is True and len(rows) == 1
    row = rows[0]
    assert (row['id'], row['record'], row['sid'], row['pid']) == (1, 42, 'S-1-5-18', '1234')
    assert int(row['time']) == TICKS
    assert row['data'] == {'ProcessGuid': '{00112233-4455-6677-8899-aabbccddeeff}', 'Image': 'first.exe', 'Image#2': 'second.exe'}


def test_recycle_and_usn_record_v2_integer_fields():
    path = 'C:\\work\\removed.txt\0'.encode('utf-16-le')
    recycle = struct.pack('<QQQI', 2, 123456789, TICKS, len(path)//2) + path
    out = win.recycle_i(recycle)
    assert (out['original_path'], out['file_size'], int(out['deleted_time'])) == (r'C:\work\removed.txt', 123456789, TICKS)
    name = 'renamed.txt'.encode('utf-16-le')
    length = (60 + len(name) + 7) // 8 * 8
    rec = bytearray(length)
    struct.pack_into('<IHHQQQQIIIIHH', rec, 0, length, 2, 0,
                     0x000300000000002A, 0x0002000000000005, 900, TICKS,
                     0x80002000, 0, 99, 0x20, len(name), 60)
    rec[60:60+len(name)] = name
    parsed = win.usn_records(bytes(rec))
    assert len(parsed) == 1
    assert {k: parsed[0][k] for k in ['usn', 'name', 'file', 'parent', 'reasons', 'attributes']} == {
        'usn': 900, 'name': 'renamed.txt', 'file': 42, 'parent': 5,
        'reasons': ['rename_new_name', 'close'], 'attributes': 0x20}
    assert int(parsed[0]['time']) == TICKS


PARSERS = [win.open_registry, win.lnk, win.prefetch, win.jumplist, win.task_xml,
           win.recycle_i, win.mft_record, win.mft_records, win.usn_records,
           win.parse_shimcache, win.xml_events, win.json_events, win.csv_events,
           win.evtx_chunks, win.evtx_record_count, win.evtx_header_times,
           win.evtx_events, win.evtx_slack, win.tabstate, win.wmi_hints]


@pytest.mark.parametrize('fn', PARSERS, ids=lambda fn: fn.__name__)
def test_binary_text_parsers_seeded_truncation_bitflip_fuzz(fn):
    rng = random.Random(707)
    corpus = [b'', b'\xff' * 256, b'\0' * 256, b'x' * 16384]
    corpus += [rng.randbytes(n) for n in [1, 8, 31, 77, 256]]
    for valid in [lnk_fixture(), hive_fixture(), evtx_fixture()[:0x1240]]:
        corpus += [valid[:n] for n in [4, 20, 75, 128]]
        changed = bytearray(valid); changed[len(valid)//2] ^= 0x80; corpus.append(bytes(changed))
    for value in corpus:
        closed(fn, value)


@pytest.mark.parametrize('fn', [win.filetime, win.from_unix, win.parse_time])
def test_timestamp_malformed_values(fn):
    for value in [None, '', 'bad', [], {}, -1, 1 << 1000]:
        closed(fn, value)


def test_filetime_infinite_fail_closed():
    closed(win.filetime, float('inf'))


def test_parse_time_timezone_underflow_fail_closed():
    closed(win.parse_time, '0001-01-01T00:00:00+01:00')


def test_cli_missing_arguments_returns_status(capsys):
    assert win.main([]) == 2
