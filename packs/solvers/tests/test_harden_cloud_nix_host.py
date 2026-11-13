"""Independent Linux/macOS host artifact fixtures; all content stays inert.

Oracles: passwd/group field grammar, systemd unit and journal documentation,
stdlib plistlib, JSON writer, and exact datetime/hash arithmetic.
"""
from datetime import datetime, timezone
import base64
import hashlib
import json
import plistlib
import random
import socket
import subprocess

import pytest

import nix_host as engine

nh = engine.nh
PASSWD = 'root:x:0:0:root:/root:/bin/sh\nfixture:x:1001:1002:Fixture:/home/fixture:/bin/bash\n'
UNIT = '[Unit]\nDescription=Fixture\n[Service]\nUser=fixture\nExecStart=/old\nExecStart=\nExecStart=/usr/bin/printf safe\n[Install]\nWantedBy=multi-user.target\n'
CRON = 'SHELL=/bin/sh\n*/5 * * * * root /usr/bin/printf safe\n'


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('artifact inspection attempted execution/network')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


def test_passwd_group_and_unit_field_semantics():
    out = nh.parse_passwd(PASSWD)
    assert (out[1]['name'], out[1]['uid'], out[1]['gid'], out[1]['home']) == ('fixture', 1001, 1002, '/home/fixture')
    assert nh.parse_group('staff:x:1002:fixture,second\n')[0]['members'] == ['fixture', 'second']
    unit = nh.parse_unit(UNIT)
    assert unit['Service']['ExecStart'] == ['/usr/bin/printf safe']
    assert unit['Service']['User'] == ['fixture']
    assert engine.classify('service.conf', UNIT.encode())[0] == 'unit'
    tab = nh.parse_crontab(CRON, system=True)
    assert tab['env'] == {'SHELL': '/bin/sh'}
    assert tab['jobs'][0]['user'] == 'root'
    assert tab['jobs'][0]['command'] == '/usr/bin/printf safe'
    assert tab['jobs'][0]['schedule'] == '*/5 * * * *'


def test_plistlib_launchd_and_persistence_rows():
    document = {'Label': 'org.fixture.job', 'ProgramArguments': ['/usr/bin/printf', 'safe'],
                'RunAtLoad': True, 'UserName': 'fixture'}
    for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML):
        raw = plistlib.dumps(document, fmt=fmt)
        assert engine.classify('job.plist', raw) == ('plist', document)
        rows = engine.persistence_rows({'/Library/LaunchDaemons/org.fixture.job.plist': raw,
                                       '/etc/cron.d/fixture': CRON.encode(), '/etc/systemd/system/fixture.service': UNIT.encode()})
        launch = next(row for row in rows if row['name'] == 'org.fixture.job')
        assert launch['command'] == '/usr/bin/printf safe'
        assert launch['trigger'] == 'RunAtLoad'
        assert any(row['mechanism'] == 'cron' and row['author'] == 'root' for row in rows)


def test_json_logs_and_timestamps_from_exact_arithmetic():
    instant = datetime(2020, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
    unix_us = 1577934245123456
    journal = nh.parse_journal_json(json.dumps({'__REALTIME_TIMESTAMP': str(unix_us),
        'MESSAGE': 'CSCTF{journal}', '_HOSTNAME': 'fixture', '_PID': '42'}))[0]
    assert journal['time'] == instant
    assert journal['msg'] == 'CSCTF{journal}'
    docker = nh.parse_docker_log(json.dumps({'time': '2020-01-02T03:04:05.123456789Z',
        'stream': 'stderr', 'log': 'CSCTF{docker}\n'}))[0]
    assert docker['time'] == instant
    assert docker['log'] == 'CSCTF{docker}'
    assert nh.parse_history('#1577934245\nprintf safe\n')[0] == {
        'n': 1, 'time': 1577934245, 'command': 'printf safe'}


def test_authorized_key_fingerprint_and_quoted_options():
    blob = b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))
    text = 'command="printf safe",no-pty ssh-ed25519 ' + base64.b64encode(blob).decode() + ' fixture'
    record = nh.parse_authorized_keys(text)[0]
    assert record['options'] == {'command': 'printf safe', 'no-pty': True}
    assert record['sha256'] == 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


@pytest.mark.parametrize('parser', [nh.parse_syslog, nh.parse_journal_json, nh.parse_journal_export,
    nh.parse_docker_log, nh.parse_audit, nh.parse_crontab, nh.parse_unit, nh.parse_passwd,
    nh.parse_shadow, nh.parse_group, nh.parse_authorized_keys, nh.parse_ld_preload, nh.parse_history])
def test_text_parsers_deterministic_fuzz(parser, monkeypatch):
    rng = random.Random(12345)
    samples = ['', '\xff' * 64] + [rng.randbytes(n).decode('latin-1') for n in (1, 8, 32, 256)]
    for valid in (PASSWD, UNIT, CRON):
        samples.extend([valid[:1], valid[:8], valid[:-1]])
        changed = bytearray(valid.encode())
        changed[rng.randrange(len(changed))] ^= 128
        samples.append(changed.decode('latin-1'))
    for sample in samples:
        if parser is nh.parse_passwd and sample == PASSWD.replace('1002', '100²'):
            continue  # This exact mutation is independently isolated below.
        parser(sample)
    monkeypatch.setattr(nh, 'MAX_LINES', 2)
    parser('invalid\n' * 100)


def test_classifier_binary_truncation_and_text_size_cap(monkeypatch):
    raw = plistlib.dumps({'Label': 'fixture'}, fmt=plistlib.FMT_BINARY)
    for data in [b'', b'\xff' * 100] + [raw[:i] for i in range(len(raw))]:
        engine.classify('fixture', data)
    monkeypatch.setattr(engine, 'MAX_FILE', 16)
    assert engine.classify('large.txt', b'a' * 17) == ('big', None)


@pytest.mark.parametrize('parser,text', [
    (nh.parse_passwd, 'a:x:²:0:a:/a:/bin/sh'),
    (nh.parse_passwd, 'a:x:' + '9' * 5000 + ':0:a:/a:/bin/sh'),
    (nh.parse_passwd, PASSWD.replace('1002', '100²')),
    (nh.parse_group, 'a:x:²:b'),
])
def test_invalid_account_numeric_fields_fail_closed(parser, text):
    assert parser(text) is None


def test_huge_journal_time_fails_closed():
    nh.parse_journal_json(json.dumps({'MESSAGE': 'safe', '__REALTIME_TIMESTAMP': '9' * 500}))


@pytest.mark.parametrize('stamp', ['2020-01-01T00:00:00+99:99', '2020-01-01T00:00:00-99:99'])
def test_bad_iso_offset_fails_closed(stamp):
    assert nh.parse_iso(stamp) == (None, False)
