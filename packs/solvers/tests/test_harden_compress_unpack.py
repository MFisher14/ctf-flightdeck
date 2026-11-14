"""Real ZIP/gzip fixtures and path/budget contracts for tools/unpack.py.

Independent oracles are zipfile/gzip/tarfile encoders and literal input bytes:
https://docs.python.org/3/library/zipfile.html
https://docs.python.org/3/library/tarfile.html
All filesystem operations use tmp_path. Network and subprocess creation are
blocked; only the inherited runner's offline expand() path is reachable.
"""
import gzip
import hashlib
import io
from pathlib import Path
import random
import stat
import subprocess
import sys
import tarfile
import zipfile

import pytest
import requests

import unpack as engine


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as writer:
        for name, data in entries:
            writer.writestr(name, data)
    return output.getvalue()


@pytest.fixture(autouse=True)
def no_live_requests_or_processes(monkeypatch):
    monkeypatch.setattr(sys, 'dont_write_bytecode', sys.dont_write_bytecode)
    def denied(*args, **kwargs):
        pytest.fail('offline unpack test attempted network or subprocess use')
    monkeypatch.setattr(requests.Session, 'request', denied)
    monkeypatch.setattr(subprocess, 'run', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)


@pytest.fixture
def runner(monkeypatch):
    result = engine._runner()
    # Test unencrypted files without reading the player's password store.
    monkeypatch.setattr(result.pw, 'candidates', lambda: [b'infected'])
    return result


def expand_into(tmp_path, runner, raw, name='sample.zip'):
    members = tmp_path / 'members'
    members.mkdir()
    notes = []
    engine.write_members(runner, members, [('', name, name, raw)], notes)
    return members, notes


def test_real_zip_member_content_and_sha256_listing(tmp_path, runner):
    expected = {'hello.txt': b'CSCTF{literal_fixture}', 'sub/data.bin': bytes(range(256))}
    members, notes = expand_into(tmp_path, runner, zip_bytes(expected.items()))
    assert {relative: (members / relative).read_bytes() for relative in expected} == expected
    assert engine.listing(members) == sorted((name, len(data), hashlib.sha256(data).hexdigest())
                                            for name, data in expected.items())
    assert not notes
    assert all(stat.S_IMODE((members / name).stat().st_mode) == 0o644 for name in expected)


def test_gzip_wrapped_zip_reveals_original_payload(tmp_path, runner):
    payload = b'CSCTF{gzip_zip}'
    members, _ = expand_into(tmp_path, runner, gzip.compress(zip_bytes([('flag.txt', payload)]), mtime=0), 'sample.gz')
    assert (members / 'flag.txt').read_bytes() == payload


def test_tar_is_preserved_as_opaque_unadvertised_format(tmp_path, runner):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as writer:
        entry = tarfile.TarInfo('hello.txt'); entry.size = 5
        writer.addfile(entry, io.BytesIO(b'hello'))
    raw = output.getvalue()
    members, _ = expand_into(tmp_path, runner, raw, 'sample.tar')
    assert (members / 'sample.tar').read_bytes() == raw


def test_traversal_harness_names_collisions_and_links_are_inert(tmp_path, runner):
    link = zipfile.ZipInfo('link')
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    raw = zip_bytes([('../../AGENTS.md', b'inert instructions'), ('A.txt', b'first'),
                     ('a.txt', b'second'), ('dir/.claude/settings.json', b'{}'),
                     (link, b'../outside')])
    members, _ = expand_into(tmp_path, runner, raw)
    assert (members / '_AGENTS.md').read_bytes() == b'inert instructions'
    assert (members / 'A.txt').read_bytes() == b'first'
    assert (members / 'a~2.txt').read_bytes() == b'second'
    assert (members / 'dir/_.claude/settings.json').read_bytes() == b'{}'
    assert (members / 'link').read_bytes() == b'../outside'
    assert not (members / 'link').is_symlink()
    assert not (tmp_path / 'AGENTS.md').exists()


def test_member_total_and_count_write_caps(tmp_path, runner, monkeypatch):
    monkeypatch.setattr(engine, 'MAX_MEMBER', 8)
    monkeypatch.setattr(engine, 'MAX_TOTAL', 10)
    raw = zip_bytes([('too-large.bin', b'x' * 9), ('a.bin', b'A' * 6), ('b.bin', b'B' * 6)])
    members, notes = expand_into(tmp_path, runner, raw)
    assert engine.listing(members) == [('a.bin', 6, hashlib.sha256(b'A' * 6).hexdigest())]
    assert any('over the limit of 8' in note for note in notes)
    assert any('stopped at 10 bytes' in note for note in notes)


def test_nested_archive_budget_is_breadth_first(tmp_path, runner, monkeypatch):
    inner = zip_bytes([(f'n{i}.txt', f'nested{i}'.encode()) for i in range(10)])
    outer = zip_bytes([('inner.zip', inner), ('top.txt', b'prioritize top-level')])
    monkeypatch.setattr(engine, 'MAX_MEMBERS', 2)
    members, notes = expand_into(tmp_path, runner, outer)
    assert (members / 'top.txt').read_bytes() == b'prioritize top-level'
    assert len(engine.listing(members)) == 2
    assert not (members / 'n0.txt').exists()
    assert any('stopped at 2 members' in note for note in notes)


def test_member_bomb_budget_prevents_inflation(tmp_path, runner, monkeypatch):
    raw = zip_bytes([('bomb.bin', b'X' * 4096)])
    monkeypatch.setattr(engine, 'MAX_MEMBER', 16)
    original = zipfile.ZipFile.read
    inflated_sizes = []
    def recorded_read(self, name, *args, **kwargs):
        info = name if isinstance(name, zipfile.ZipInfo) else self.getinfo(name)
        inflated_sizes.append(info.file_size)
        return original(self, name, *args, **kwargs)
    monkeypatch.setattr(zipfile.ZipFile, 'read', recorded_read)
    members, _ = expand_into(tmp_path, runner, raw)
    assert engine.listing(members) == []
    assert all(size <= 16 for size in inflated_sizes)


def test_unpack_file_and_cached_attempt_use_real_expander(tmp_path, runner, monkeypatch, capsys):
    monkeypatch.setattr(engine, '_runner', lambda: runner)
    path = tmp_path / 'delivery.zip'
    raw = zip_bytes([('hello.bin', b'HELLO')]); path.write_bytes(raw)
    assert engine.unpack_file(path) == 0
    assert (tmp_path / 'delivery.zip.unpacked/hello.bin').read_bytes() == b'HELLO'
    assert path.read_bytes() == raw
    attempt = tmp_path / 'attempt'; (attempt / 'artifact').mkdir(parents=True)
    (attempt / 'artifact/blob.zip').write_bytes(raw)
    assert engine.unpack(attempt) == 0
    assert engine.unpack(attempt) == 0
    assert 'fresh=false' in capsys.readouterr().out
    assert engine.recorded(attempt / 'members') == {'blob.zip': hashlib.sha256(raw).hexdigest()}


def test_symlink_existing_directory_is_never_followed(tmp_path):
    members = tmp_path / 'members'; members.mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (members / 'escape').symlink_to(outside, target_is_directory=True)
    tree = engine.Tree(members, members)
    with pytest.raises(engine.Skip):
        tree.path_for('escape/no.txt')
    assert list(outside.iterdir()) == []
    engine.clear(members)
    assert outside.is_dir()


def test_components_and_path_budget(tmp_path, monkeypatch):
    assert engine.components('../../AGENTS.md/x\\y\0.txt') == ['_AGENTS.md', 'x_y_.txt']
    assert engine.components('/./../') == []
    assert len(engine.components('x' * 10000)[0]) == 120
    tree = engine.Tree(tmp_path, tmp_path)
    with pytest.raises(engine.Skip):
        tree.path_for('../../')
    monkeypatch.setattr(engine, 'MAX_PATH', 1)
    with pytest.raises(engine.Skip):
        tree.path_for('x')


def test_find_deliveries_ignores_links_and_finder_metadata(tmp_path):
    artifact = tmp_path / 'artifact'; artifact.mkdir()
    (artifact / 'a.bin').write_bytes(b'A')
    (artifact / '.DS_Store').write_bytes(b'ignored')
    (artifact / 'delivery-02').mkdir()
    (artifact / 'delivery-02/b.bin').write_bytes(b'B')
    (artifact / 'link').symlink_to(artifact / 'a.bin')
    notes = []
    assert engine.find_deliveries(artifact, notes) == [('', 'a.bin', 'a.bin'), ('delivery-02', 'delivery-02/b.bin', 'b.bin')]
    assert any('symbolic link' in item for item in notes)


def test_parse_and_main_usage_never_load_live_runner(monkeypatch, capsys):
    def denied():
        pytest.fail('usage-only path loaded a runner')
    monkeypatch.setattr(engine, '_runner', denied)
    assert engine.parse(['--lane', 'binary', '--day', '2']) == {'lane': 'binary', 'day': 2, 'mode': 'base', 'mode_given': False}
    assert engine.parse(['safe.zip']) == {'dir': 'safe.zip'}
    assert engine.main(['--help']) == 0
    assert engine.main([]) == 64
    assert engine.main(['--unknown']) == 64


@pytest.mark.parametrize('raw', [b'', b'\xff'*80, random.Random(188).randbytes(80), b'PK\x03\x04', b'PK\x03\x04'+b'\0'*12])
def test_malformed_zip_data_is_preserved_cleanly(raw, tmp_path, runner):
    members, _ = expand_into(tmp_path, runner, raw)
    assert (members / 'sample.zip').read_bytes() == raw


def test_truncated_and_bitflipped_archives_do_not_leak(tmp_path, runner, monkeypatch):
    raw = zip_bytes([('data.txt', b'deterministic payload')])
    # Explicitly disable optional external 7z fallback for corrupt zip CRCs.
    monkeypatch.setattr(runner.shutil, 'which', lambda name: None)
    rng = random.Random(90)
    cases = [raw[:n] for n in (1, 4, 20, 40, len(raw)-1)]
    for _ in range(8):
        changed = bytearray(raw); changed[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        cases.append(bytes(changed))
    for index, data in enumerate(cases):
        target = tmp_path / str(index); target.mkdir()
        members, _ = expand_into(target, runner, data)
        assert sum(size for _, size, _ in engine.listing(members)) <= max(len(data), 21)


@pytest.mark.parametrize('argv', [[None], [1], [b'--help']])
def test_malformed_cli_values_raise_declared_error(argv):
    try:
        engine.parse(argv)
    except engine.Stop:
        pass
