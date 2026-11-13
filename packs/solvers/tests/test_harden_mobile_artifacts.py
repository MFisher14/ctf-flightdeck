"""Independent vector locks and deterministic parser regression fuzz.

Oracles: Python plistlib/zipfile/sqlite3; SQLite's published fileformat2.html;
AOSP XmlUtils writeValueXml; published pymobiledevice MBDB_SIGNATURE.
The base/WAL below were emitted by SQLite, never by the engine. They encode:
CREATE TABLE messages(body TEXT, timestamp INTEGER); then a checkpoint, then
INSERT rows ('CSCTF{sqlite}',20), ('second',100). Salt bytes are frozen so fuzz
inputs are reproducible. Test SQL operates only on these self-authored fixtures.
"""
import base64
from datetime import datetime
import hashlib
import io
import json
import plistlib
import random
import sqlite3
import struct
import zipfile
import zlib

import pytest
import mobile_artifacts as m


BASE = zlib.decompress(base64.b64decode(
    'eJwLDvTJLElVSMsvyk0sUTBmYGFgYmJwUFBgYGBggmIYYARiFjQ+IcDEoNclwgtSzLyeAYhGwSgYBeQDf0Y2cVlZxuKSxKSc1NzU4uLE9NRiGM3kHOTqGOKqEOLo5OOqABPVSMpPqVQIcY0I0VEoyQSKliTmFih4+oW4ursGaYLyJkquHgWjYBSMGAAAR4QiTQ=='))
WAL = zlib.decompress(base64.b64decode(
    'eJwzr2drYtB9JMHAwMIABIwZEe80FZiYxP/vja4+P9vUASjGBMIw8eiwjLk2wlKdvCBB5ocMzG+BxCgYBaNgeAEuJmZJxuLU5Py8lBRBRmZ1Rudg5xC36uLCnMyS1FoRAKGVGMo='))
PLIST_VALUE = {'name': 'CSCTF{plist}', 'enabled': True, 'count': -17,
               'ratio': 1.25, 'nested': ['a', {'b': 2}],
               'data': b'\x00\xff\x01', 'uid': plistlib.UID(7),
               'date': datetime(2026, 11, 5, 12, 30, 0)}
PLIST = plistlib.dumps(PLIST_VALUE, fmt=plistlib.FMT_BINARY, sort_keys=True)
KEYED = plistlib.dumps({'$archiver': 'NSKeyedArchiver', '$version': 100000,
                       '$objects': ['$null', {'Size': 41, 'Name': 'CSCTF{keyed}'}],
                       '$top': {'root': plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)
PREFS = (b'<map><string name="name">CSCTF{prefs} &amp; x</string>'
         b'<int name="count" value="-17"/><long name="big" value="4294967296"/>'
         b'<float name="ratio" value="1.25"/><boolean name="enabled" value="true"/>'
         b'<set name="items"><string>a</string><string>b</string></set></map>')
PREFS_EXPECTED = {'name': 'CSCTF{prefs} & x', 'count': -17, 'big': 4294967296,
                  'ratio': 1.25, 'enabled': True, 'items': ['a', 'b']}


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 5, 12, 0, 0))
            archive.writestr(info, data)
    return stream.getvalue()


ZIP = zip_bytes([('shared_prefs/settings.xml', PREFS), ('assets/blob', b'\x00\xff')])


def database(sql, rows=()):
    conn = sqlite3.connect(':memory:')
    try:
        conn.execute('PRAGMA page_size=1024')
        conn.execute(sql)
        for statement, args in rows:
            conn.execute(statement, args)
        conn.commit()
        return conn.serialize()
    finally:
        conn.close()


def oracle_rows(data, table):
    conn = sqlite3.connect(':memory:')
    try:
        conn.deserialize(data)
        return conn.execute(f'SELECT rowid,* FROM {table} ORDER BY rowid').fetchall()
    finally:
        conn.close()


def test_vector_binary_plist_matches_plistlib():
    oracle = plistlib.loads(PLIST)
    actual = m.parse_plist_metadata(PLIST)
    assert actual['format'] == 'binary'
    assert actual['root_type'] == 'dict'
    for key in ('name', 'enabled', 'count', 'ratio', 'nested'):
        assert actual['value'][key] == oracle[key]
    assert actual['value']['uid'] == {'type': 'uid', 'value': oracle['uid'].data}
    assert actual['value']['date'] == oracle['date'].isoformat()
    assert actual['value']['data'] == {
        'type': 'data', 'length': len(oracle['data']),
        'sha256': hashlib.sha256(oracle['data']).hexdigest(), 'hex': oracle['data'].hex()}


def test_vector_keyed_archive_uid_graph():
    # UID/reference structure from Apple's NSKeyedArchiver serialized plist.
    value = {'$archiver': 'NSKeyedArchiver', '$version': 100000,
             '$objects': ['$null', {'NS.keys': [plistlib.UID(2)],
                                     'NS.objects': [plistlib.UID(3)]},
                          'answer', 'CSCTF{keyed}'], '$top': {'root': plistlib.UID(1)}}
    raw = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
    readback = plistlib.loads(raw)
    objects = readback['$objects']
    container = objects[readback['$top']['root'].data]
    expected = {objects[container['NS.keys'][0].data]: objects[container['NS.objects'][0].data]}
    assert m.decode_keyed_archive(raw) == {
        'archiver': 'NSKeyedArchiver', 'version': 100000, 'root': expected}


def test_vector_shared_preferences_aosp_types():
    # https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r4/core/java/com/android/internal/util/XmlUtils.java
    assert m.parse_shared_preferences(PREFS) == {
        'entry_count': len(PREFS_EXPECTED), 'values': PREFS_EXPECTED}


def test_vector_sqlite_image_public_methods_and_wrapper():
    blob = bytes(range(256)) * 20  # force real overflow pages, not engine encoding
    raw = database('CREATE TABLE t(label TEXT, value INTEGER, data BLOB, ratio REAL)', [
        ('INSERT INTO t VALUES (?,?,?,?)', ('CSCTF{row}', -2**40, blob, 1.25)),
        ('INSERT INTO t VALUES (?,?,?,?)', ('other', 0, None, -0.5))])
    oracle = oracle_rows(raw, 't')
    conn = sqlite3.connect(':memory:')
    conn.deserialize(raw)
    root, sql = conn.execute("SELECT rootpage, sql FROM sqlite_schema WHERE name='t'").fetchone()
    conn.close()
    image = m.SQLiteImage(raw)
    assert image.page(1) == raw[:1024]
    assert image.schema()[0]['sql'] == sql
    assert image.schema()[0]['root_page'] == root
    assert [(r['rowid'], *r['values']) for r in image.table_rows(root)] == oracle
    for out in (image.report(), m.parse_sqlite(raw), m.analyze_sqlite(raw)['base']):
        rows = out['tables']['t']['rows']
        assert [(r['rowid'], *r['values'].values()) for r in rows] == oracle


def test_vector_wal_sqlite_emitted_fixture(tmp_path):
    # Let SQLite itself read its own WAL; never synthesize checksums via engine.
    path = tmp_path / 'oracle.db'
    path.write_bytes(BASE)
    path.with_name(path.name + '-wal').write_bytes(WAL)
    conn = sqlite3.connect(path)
    expected = conn.execute('SELECT rowid,body,timestamp FROM messages ORDER BY rowid').fetchall()
    conn.close()
    assert expected == [(1, 'CSCTF{sqlite}', 20), (2, 'second', 100)]
    wal = m.parse_wal(WAL, expected_page_size=1024)
    assert wal['header_checksum_valid']
    assert all(r['chain_valid'] and r['checksum_valid'] and r['salt_valid'] for r in wal['frames'])
    assert wal['page_size'] == 1024
    assert len(wal['frames']) == (len(WAL) - 32) // (1024 + 24)
    assert wal['trailing_bytes'] == 0
    report = m.analyze_sqlite(BASE, WAL)
    assert report['base']['tables']['messages']['rows'] == []
    for view in ('committed', 'latest'):
        rows = report[view]['tables']['messages']['rows']
        assert [(r['rowid'], r['values']['body'], r['values']['timestamp']) for r in rows] == expected


def test_vector_mbdb_published_signature_empty_record_stream():
    # Public reference: bkerler/pymobiledevice mobilebackup2.py MBDB_SIGNATURE.
    assert m.parse_mbdb(b'mbdb\x05\x00') == {'version': [5, 0], 'record_count': 0, 'records': []}


def test_vector_ios_backup_plist_and_manifest_sqlite():
    meta = plistlib.dumps({'$archiver': 'NSKeyedArchiver', '$version': 100000,
                          '$objects': ['$null', {'Size': 41}],
                          '$top': {'root': plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)
    manifest = database('CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)', [
        ('INSERT INTO Files VALUES(?,?,?,?,?)', ('a'*40, 'HomeDomain', 'Library/Preferences/app.plist', 1, meta))])
    info = plistlib.dumps({'Device Name': 'Fixture'}, fmt=plistlib.FMT_BINARY)
    files = {'Manifest.db': manifest, 'Info.plist': info, 'aa/' + 'a'*40: PLIST}
    out = m.analyze_ios_backup(files)
    expected = oracle_rows(manifest, 'Files')[0]
    assert (out['files'][0]['rowid'], out['files'][0]['file_id'], out['files'][0]['domain'],
            out['files'][0]['relative_path'], out['files'][0]['flags']) == expected[:5]
    assert out['files'][0]['metadata']['root'] == {'Size': 41}
    assert out['files'][0]['body_present']
    assert out['plists']['Info.plist']['value'] == plistlib.loads(info)


def test_vector_android_appdata_and_bundle_zip_oracle(tmp_path, capsys):
    with zipfile.ZipFile(io.BytesIO(ZIP)) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    for out in (m.analyze_android_appdata(entries), m.analyze_bundle(ZIP, 'android')):
        assert out['preferences'][0]['report']['values'] == PREFS_EXPECTED
        assert out['other_files'][0]['sha256'] == hashlib.sha256(entries['assets/blob']).hexdigest()
        assert out['other_files'][0]['size'] == len(entries['assets/blob'])
    path = tmp_path / 'bundle.zip'
    path.write_bytes(ZIP)
    assert m.main([str(path), '--platform', 'android']) == 0
    assert json.loads(capsys.readouterr().out)['preferences'][0]['report']['values'] == PREFS_EXPECTED


def test_vector_schema_classifier_independent_table_sets():
    # This API is a heuristic, so lock unambiguous disjoint schema names only.
    assert m.classify_messaging_schema({'tables': {'messages': {}, 'chat': {}, 'jid': {}}}) == {
        'family': 'whatsapp', 'whatsapp_tables': ['chat', 'jid', 'messages'], 'signal_tables': [], 'confidence': 'high'}
    assert m.classify_messaging_schema({'tables': {'sms': {}, 'mms': {}, 'thread': {}}}) == {
        'family': 'signal', 'whatsapp_tables': [], 'signal_tables': ['mms', 'sms', 'thread'], 'confidence': 'high'}


def corpus(seed):
    rng = random.Random(0xC5C7F)
    yield b''
    for size in (1, 2, 4, 8, 16, 32, 64, 127):
        yield b'\xff' * size
        yield rng.randbytes(size)
    for size in sorted({1, 4, 6, 8, 16, 32, 64, len(seed)//2, len(seed)-1}):
        yield seed[:size]
    for _ in range(24):
        raw = bytearray(seed)
        index = rng.randrange(len(raw))
        raw[index] ^= 1 << rng.randrange(8)
        yield bytes(raw)


@pytest.mark.parametrize('name,seed', [
    ('parse_sqlite', BASE), ('analyze_sqlite', BASE), ('parse_wal', WAL),
    ('parse_mbdb', b'mbdb\x05\x00'), ('parse_plist_metadata', PLIST),
    ('decode_keyed_archive', KEYED), ('parse_shared_preferences', PREFS),
])
def test_fail_closed_seeded_parser_fuzz(name, seed):
    for raw in corpus(seed):
        try:
            result = getattr(m, name)(raw)
        except m.ArtifactError:
            continue
        assert result is None or isinstance(result, dict)


def test_fail_closed_sqlite_image_fuzz():
    for raw in corpus(BASE):
        try:
            view = m.SQLiteImage(raw)
            view.report()
        except m.ArtifactError:
            pass


def test_fail_closed_wal_overlay_and_manifest_fuzz():
    for raw in corpus(WAL):
        try:
            assert isinstance(m.analyze_sqlite(BASE, raw), dict)
        except m.ArtifactError:
            pass
    for raw in corpus(BASE):
        try:
            assert isinstance(m.analyze_ios_backup({'Manifest.db': raw}), dict)
        except m.ArtifactError:
            pass


def test_fail_closed_mapping_entrypoints_fuzz():
    for raw in corpus(PLIST):
        for func, files in (
            (m.analyze_ios_backup, {'Info.plist': raw}),
            (m.analyze_android_appdata, {'shared_prefs/app.xml': raw}),
        ):
            try:
                assert isinstance(func(files), dict)
            except m.ArtifactError:
                pass


def test_fail_closed_zip_empty_noise_and_all_prefixes():
    # Member corruption is isolated below, so one known CRC bug cannot mask
    # independent coverage of envelope truncation and noise.
    rng = random.Random(223)
    for raw in [b'', b'\xff'*100, *(rng.randbytes(n) for n in range(64)),
                *(ZIP[:n] for n in range(len(ZIP)))]:
        try:
            result = m.analyze_bundle(raw)
        except m.ArtifactError:
            continue
        assert isinstance(result, dict)


def test_bug_negative_sqlite_rowid():
    raw = database('CREATE TABLE t(v TEXT)', [('INSERT INTO t(rowid,v) VALUES(?,?)', (-1, 'negative'))])
    assert m.parse_sqlite(raw)['tables']['t']['rows'][0]['rowid'] == oracle_rows(raw, 't')[0][0]


def test_bug_sqlite_integer_primary_key_alias():
    raw = database('CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)', [('INSERT INTO t VALUES(?,?)', (7, 'alias'))])
    assert m.parse_sqlite(raw)['tables']['t']['rows'][0]['values']['id'] == oracle_rows(raw, 't')[0][1]


@pytest.mark.parametrize('through_backup', [False, True])
def test_bug_plist_xml_truncation_exception(through_backup):
    try:
        raw = b'<?xml version="1.0"?><plist><dict>'
        if through_backup:
            m.analyze_ios_backup({'Info.plist': raw})
        else:
            m.parse_plist_metadata(raw)
    except m.ArtifactError:
        pass


def test_bug_keyed_archive_top_type():
    raw = plistlib.dumps({'$objects': [], '$top': []}, fmt=plistlib.FMT_BINARY)
    try:
        m.decode_keyed_archive(raw)
    except m.ArtifactError:
        pass


@pytest.mark.parametrize('through_appdata', [False, True])
def test_bug_preferences_unknown_encoding(through_appdata):
    try:
        raw = b'<?xml version="1.0" encoding="BOGUS"?><map/>'
        if through_appdata:
            m.analyze_android_appdata({'shared_prefs/settings.xml': raw})
        else:
            m.parse_shared_preferences(raw)
    except m.ArtifactError:
        pass


def test_bug_zip_crc_exception():
    raw = bytearray(ZIP)
    offset = raw.index(PREFS)
    raw[offset] ^= 1
    try:
        m.analyze_bundle(bytes(raw))
    except m.ArtifactError:
        pass


def test_bug_zip_compression_exception():
    raw = bytearray(ZIP)
    struct.pack_into('<H', raw, 8, 99)
    central = raw.index(b'PK\x01\x02')
    struct.pack_into('<H', raw, central + 10, 99)
    try:
        m.analyze_bundle(bytes(raw))
    except m.ArtifactError:
        pass


def test_bug_timeline_numeric_order():
    raw = database('CREATE TABLE messages(body TEXT, timestamp INTEGER)', [
        ('INSERT INTO messages VALUES (?,?)', ('twenty', 20)),
        ('INSERT INTO messages VALUES (?,?)', ('hundred', 100))])
    expected = sorted(row[2] for row in oracle_rows(raw, 'messages'))
    assert [r['timestamp'] for r in m.analyze_android_appdata({'msgstore.db': raw})['message_leads']] == expected


def test_bug_mbdb_bundle_auto_route():
    raw = zip_bytes([('Manifest.mbdb', b'mbdb\x05\x00')])
    assert m.analyze_bundle(raw)['platform'] == 'ios-backup'


@pytest.mark.parametrize('declaration', [
    'id INTEGER PRIMARY KEY, v TEXT',
    'id INTEGER PRIMARY KEY ASC, v TEXT',
    'id INTEGER PRIMARY KEY DESC, v TEXT',
    'id INT PRIMARY KEY, v TEXT',
    'id BIGINT PRIMARY KEY, v TEXT',
    'id INTEGER(8) PRIMARY KEY, v TEXT',
    'id INTEGER, v TEXT, PRIMARY KEY(id)',
    'id INTEGER, v TEXT, PRIMARY KEY(id DESC)',
    'id INTEGER, v TEXT, CONSTRAINT pk PRIMARY KEY(id) ON CONFLICT REPLACE',
    'id INTEGER, v TEXT, PRIMARY KEY(id,v)',
    'id INTEGER DEFAULT (0), v TEXT',
    "id INTEGER CHECK(v != 'PRIMARY KEY'), v TEXT",
    '"id" "INTEGER" PRIMARY KEY, v TEXT',
    'id INTEGER CONSTRAINT pk PRIMARY KEY, v TEXT',
    'id INTEGER /* PRIMARY KEY DESC */ PRIMARY KEY, v TEXT',
    'id "ınteger" PRIMARY KEY, v TEXT',
    "id 'ınteger' PRIMARY KEY, v TEXT",
])
def test_primary_key_alias_respects_sqlite_grammar(declaration):
    raw = database('CREATE TABLE t(' + declaration + ')', [
        ('INSERT INTO t(id,v) VALUES (?,?)', (None, 'label'))])
    expected = oracle_rows(raw, 't')[0]
    actual = m.parse_sqlite(raw)['tables']['t']['rows'][0]
    assert (actual['rowid'], actual['values']['id'], actual['values']['v']) == expected


@pytest.mark.parametrize('key_type', ['TEXT', 'INTEGER'])
def test_primary_key_identifier_matching_is_ascii_only(key_type):
    raw = database('CREATE TABLE t("K" INTEGER, "k" ' + key_type + ', v TEXT, PRIMARY KEY(k))', [
        ('INSERT INTO t(v) VALUES (?)', ('label',))])
    expected = oracle_rows(raw, 't')[0]
    actual = m.parse_sqlite(raw)['tables']['t']['rows'][0]
    assert (actual['rowid'], actual['values']['K'], actual['values']['k'], actual['values']['v']) == expected


@pytest.mark.parametrize('rowid', [-(1 << 63), -128, 0, (1 << 63) - 1])
def test_signed_rowid_boundaries(rowid):
    raw = database('CREATE TABLE t(v TEXT)', [('INSERT INTO t(rowid,v) VALUES (?,?)', (rowid, 'v'))])
    assert m.parse_sqlite(raw)['tables']['t']['rows'][0]['rowid'] == oracle_rows(raw, 't')[0][0]


def test_artifact_cli_guards(tmp_path, capsys):
    assert m.main(['--help']) == 0
    assert m.main([]) == 2
    assert m.main([str(tmp_path / 'missing.zip')]) == 2
    bad = tmp_path / 'bad.zip'
    bad.write_bytes(b'PK\x03\x04')
    assert m.main([str(bad)]) == 2
    capsys.readouterr()
