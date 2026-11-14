"""Independent byte-layout fixtures; no engine encoder/output is an oracle.

Header layout: AOSP PerformAdbBackupTask.java (android-12.0.0_r1).
Tar fixtures below encode POSIX ustar fields at published offsets by hand;
Python's tarfile reader additionally verifies the benign inventory fixture.
"""

import io
import json
import random
import tarfile
import zlib

import pytest

import ff_androidab_backup as engine


def record(name=b"apps/test/f/file", body=b"abc", *, kind=b"0", link=b"",
           size=None, prefix=b"", mode=0o640, mtime=1234567890):
    block = bytearray(512)
    block[:len(name)] = name
    for start, width, value in ((100, 8, mode), (108, 8, 1000), (116, 8, 1000),
                                (124, 12, len(body) if size is None else size),
                                (136, 12, mtime)):
        block[start:start + width] = f"{value:0{width - 1}o}".encode() + b"\0"
    block[148:156] = b"        "
    block[156:157] = kind
    block[157:157 + len(link)] = link
    block[257:265] = b"ustar\x00" + b"00"
    block[345:345 + len(prefix)] = prefix
    block[148:156] = f"{sum(block):06o}".encode() + b"\0 "
    return bytes(block) + body + bytes((-len(body)) % 512)


def tar(*records):
    return b"".join(records) + bytes(1024)


def backup(body, *, version=5, compressed=True):
    return (f"ANDROID BACKUP\n{version}\n{int(compressed)}\nnone\n".encode()
            + (zlib.compress(body) if compressed else body))


def pax(**values):
    records = []
    for key, value in values.items():
        body = f" {key}={value}\n".encode()
        count = len(body) + 1
        while len(str(count)) + len(body) != count:
            count = len(str(count)) + len(body)
        records.append(str(count).encode() + body)
    return b"".join(records)


def encrypted_header(*, version=5):
    return (f"ANDROID BACKUP\n{version}\n1\nAES-256\n".encode()
            + b"01" * 64 + b"\n" + b"23" * 64 + b"\n10000\n"
            + b"45" * 16 + b"\n" + b"67" * 96 + b"\n")


@pytest.mark.parametrize("version", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("compressed", [False, True])
def test_header_and_inventory_lock(version, compressed):
    body = tar(record(), record(b"apps/test/db/", b"", kind=b"5"),
               record(b"empty", b""))
    fixture = backup(body, version=version, compressed=compressed)
    header = engine.parse_header(fixture)
    assert header == {"format": "android-backup", "version": version,
                      "compressed": compressed, "encryption": "none", "data_offset": 24}
    result = engine.parse_backup(fixture)
    assert result["status"] == "inventoried"
    assert engine.detect_backup(fixture) is True
    members = result["inventory"]["members"]
    assert [(m["path"], m["type"], m["size"], m["header_offset"], m["data_offset"])
            for m in members] == [("apps/test/f/file", "file", 3, 0, 512),
                                  ("apps/test/db", "directory", 0, 1024, 1536),
                                  ("empty", "file", 0, 1536, 2048)]
    assert members[0]["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert members[2]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert members[0]["mode"] == 0o640
    assert members[0]["mtime"] == 1234567890
    assert result["inventory"]["total_member_bytes"] == 3
    assert result["inventory"]["tar_bytes"] == 3072
    assert result["inventory"]["eof_offset"] == 2048
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as oracle:
        assert [(m.name.rstrip("/"), m.size) for m in oracle] == [
            (m["path"], m["size"]) for m in members]
        assert oracle.extractfile("apps/test/f/file").read() == b"abc"


@pytest.mark.parametrize("version", [1, 2, 5])
def test_encrypted_metadata_no_password_work(version, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("encrypted payload must stay opaque")
    monkeypatch.setattr(engine.zlib, "decompressobj", forbidden)
    header = encrypted_header(version=version)
    parsed = engine.parse_backup(header + bytes(32))
    assert parsed["status"] == "encrypted_metadata_only"
    assert parsed["inventory"] is None
    assert parsed["payload_bytes"] == 32
    assert parsed["header"]["data_offset"] == len(header)
    assert parsed["header"]["crypto"] == {
        "cipher": "AES-256-CBC", "padding": "PKCS5/PKCS7",
        "kdf": "PBKDF2-HMAC-SHA1", "kdf_rounds": 10000,
        "version_1_legacy_pbkdf2_fallback": version == 1,
        "user_salt_hex": "01" * 64, "checksum_salt_hex": "23" * 64,
        "user_iv_hex": "45" * 16, "encrypted_key_blob_hex": "67" * 96,
        "encrypted_key_blob_bytes": 96,
    }


def test_safe_links_and_prefix():
    body = tar(record(b"file", prefix=b"apps/test/f"),
               record(b"apps/test/f/hard", b"", kind=b"1", link=b"apps/test/f/file"),
               record(b"apps/test/f/sub/link", b"", kind=b"2", link=b"../file"))
    members = engine.inventory_tar(body)["members"]
    assert [member["type"] for member in members] == ["file", "hardlink", "symlink"]
    assert [member["resolved_target"] for member in members[1:]] == ["apps/test/f/file"] * 2


def test_pax_overrides_are_applied_before_inventory():
    body = tar(record(b"PaxHeader", pax(path="apps/test/f/café", size="3"), kind=b"x"),
               record(b"ignored", b"abc", size=0))
    result = engine.inventory_tar(body)
    assert result["member_count"] == 1
    assert result["header_count"] == 2
    assert result["members"][0]["path"] == "apps/test/f/café"
    assert result["members"][0]["size"] == 3
    assert result["members"][0]["header_offset"] == 1024


def test_global_pax_and_attribute_deletion():
    body = tar(record(b"Global", pax(path="global"), kind=b"g"),
               record(b"first"), record(b"Pax", pax(path=""), kind=b"x"),
               record(b"second"), record(b"Global", pax(path=""), kind=b"g"),
               record(b"third"))
    assert [m["path"] for m in engine.inventory_tar(body)["members"]] == ["global", "second", "third"]


@pytest.mark.parametrize("name", [b"../escape", b"/absolute", b"C:/drive", b"C:relative",
                                 b"a\\b", b"a/../../escape", b"a/../b", b"//server/share",
                                 b"a/space ", b"a/dot.", b".", b"a\x00bad", b"bad\xff"])
def test_unsafe_member_paths(name):
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(tar(record(name)))


@pytest.mark.parametrize("target", [b"../../escape", b"/absolute", b"C:/x", b"a\\b", b"self",
                                    b"other/../file"])
def test_unsafe_link_targets(target):
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(tar(record(b"dir/self", b"", kind=b"2", link=target)))


@pytest.mark.parametrize("records", [
    [record(b"a", b"", kind=b"2", link=b"b"), record(b"a/file")],
    [record(b"a/file"), record(b"a", b"", kind=b"2", link=b"b")],
    [record(b"a", b"", kind=b"2", link=b"b"), record(b"b", b"", kind=b"2", link=b"a")],
    [record(b"a", b"", kind=b"2", link=b"b"), record(b"b", b"", kind=b"2", link=b"c")],
    [record(b"a", b"", kind=b"1", link=b"missing")],
    [record(b"a"), record(b"a/file")],
    [record(b"a"), record(b"./a")],
])
def test_link_chains_aliases_and_non_directory_parents(records):
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(tar(*records))


@pytest.mark.parametrize("value", ["../escape", "/absolute", "C:/x"])
def test_pax_cannot_hide_path_escape(value):
    fixture = tar(record(b"Pax", pax(path=value), kind=b"x"), record(b"safe"))
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(fixture)


@pytest.mark.parametrize("kind", [b"3", b"4", b"6", b"S", b"L", b"K"])
def test_special_and_gnu_tar_types_rejected(kind):
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(tar(record(kind=kind)))


@pytest.mark.parametrize("body", [b"11 path=a\n", b"0 path=a\n", b"999 path=a\n", b"x path=a\n",
                                 b"9 path=a!", b"9 pat=a\n", b"10 path=a\n10 path=b\n",
                                 b"18 GNU.sparse.x=1\n"])
def test_bad_pax_records_fail_closed(body):
    with pytest.raises(engine.AndroidBackupError):
        engine.inventory_tar(tar(record(b"Pax", body, kind=b"x"), record()))


def test_sparse_pax_rejected():
    with pytest.raises(engine.AndroidBackupError, match="sparse"):
        engine.inventory_tar(tar(record(b"Pax", pax(**{"GNU.sparse.map": "0,3"}), kind=b"x"), record()))


@pytest.mark.parametrize("blob", [b"", b"ANDROID BACKUP", b"ANDROID BACKUP\r\n5\n1\nnone\n",
                                 b"ANDROID BACKUP\n0\n1\nnone\n", b"ANDROID BACKUP\n6\n1\nnone\n",
                                 b"ANDROID BACKUP\n05\n1\nnone\n", b"ANDROID BACKUP\n5\n2\nnone\n",
                                 b"ANDROID BACKUP\n5\n1\nAES-128\n", b"ANDROID BACKUP\n5\n1\nnone",
                                 b"ANDROID BACKUP\n" + b"1" * 9000 + b"\n1\nnone\n"])
def test_invalid_header(blob):
    with pytest.raises(engine.AndroidBackupError):
        engine.parse_header(blob)


@pytest.mark.parametrize("index,replacement", [(4, b"00"), (4, b"zz" * 64), (5, b"ab" * 63),
                                               (6, b"0"), (6, b"2147483648"), (6, b"+10000"),
                                               (7, b"00" * 15), (8, b"00" * 95)])
def test_invalid_crypto_metadata(index, replacement):
    lines = encrypted_header().split(b"\n")
    lines[index] = replacement
    with pytest.raises(engine.AndroidBackupError):
        engine.parse_header(b"\n".join(lines))


@pytest.mark.parametrize("body", [b"", bytes(15), bytes(17)])
def test_invalid_ciphertext_length(body):
    with pytest.raises(engine.AndroidBackupError):
        engine.parse_backup(encrypted_header() + body)


@pytest.mark.parametrize("transform", [lambda b: b[:-1], lambda b: b + b"junk",
                                       lambda b: b + zlib.compress(bytes(1024)),
                                       lambda b: b[:2] + bytes([b[2] ^ 255]) + b[3:]])
def test_zlib_integrity_and_trailing_data(transform):
    payload = zlib.compress(tar(record()))
    with pytest.raises(engine.AndroidBackupError):
        engine.parse_backup(b"ANDROID BACKUP\n5\n1\nnone\n" + transform(payload))


def test_tar_checksum_eof_padding_and_truncation():
    valid = tar(record())
    checksum_bad = bytearray(valid)
    checksum_bad[100] ^= 1
    padding_bad = bytearray(valid)
    padding_bad[520] = 1
    for bad in (bytes(checksum_bad), bytes(padding_bad), valid[:1024], valid[:-512],
                valid[:-1], valid + bytes(511) + b"x", bytes(512)):
        with pytest.raises(engine.AndroidBackupError):
            engine.inventory_tar(bad)


@pytest.mark.parametrize("limits", [engine.Limits(max_input=20), engine.Limits(max_output=1024),
                                    engine.Limits(max_member=2), engine.Limits(max_total=2),
                                    engine.Limits(max_members=1), engine.Limits(max_path=3),
                                    engine.Limits(max_ratio=1)])
def test_resource_limits(limits):
    with pytest.raises(engine.AndroidBackupError):
        engine.parse_backup(backup(tar(record(), record(b"second"))), limits=limits)


def test_pax_link_depth_limits():
    cases = [(tar(record(b"Pax", pax(path="longer"), kind=b"x"), record()), engine.Limits(max_pax=2)),
             (tar(record(b"a", b"", kind=b"2", link=b"x"), record(b"b", b"", kind=b"2", link=b"x")),
              engine.Limits(max_links=1)),
             (tar(record(b"Pax", pax(path="/".join(["a"] * 129)), kind=b"x"), record()), engine.Limits())]
    for fixture, limits in cases:
        with pytest.raises(engine.AndroidBackupError):
            engine.inventory_tar(fixture, limits=limits)


def test_actual_bomb_and_cumulative_limits():
    with pytest.raises(engine.AndroidBackupError, match="output/ratio"):
        engine.parse_backup(backup(bytes(1024 * 1024)))
    with pytest.raises(engine.AndroidBackupError, match="cumulative"):
        engine.inventory_tar(tar(record(b"first"), record(b"second")),
                             limits=engine.Limits(max_member=3, max_total=5))
    with pytest.raises(engine.AndroidBackupError, match="header count"):
        engine.inventory_tar(tar(record(b"Pax", pax(path="known"), kind=b"x"), record()),
                             limits=engine.Limits(max_members=1))


def test_inherited_pax_metadata_amplification_is_bounded():
    inherited = record(b"Global", pax(comment="A" * 400), kind=b"g")
    one = tar(inherited, record(b"first"))
    many = tar(inherited, record(b"first"), record(b"second"), record(b"third"))
    limits = engine.Limits(max_metadata=1000)
    assert engine.inventory_tar(one, limits=limits)["member_count"] == 1
    with pytest.raises(engine.AndroidBackupError, match="cumulative inventory metadata"):
        engine.inventory_tar(many, limits=limits)
    accumulated = tar(record(b"Global", pax(comment="A" * 40), kind=b"g"),
                      record(b"Global", pax(note="B" * 40), kind=b"g"), record())
    with pytest.raises(engine.AndroidBackupError, match="accumulated global PAX"):
        engine.inventory_tar(accumulated, limits=engine.Limits(max_pax=70))


@pytest.mark.parametrize("kwargs", [{"max_input": 0}, {"max_output": -1}, {"max_ratio": True},
                                    {"max_input": 2**40}, {"max_members": 100001}, {"max_path": 65537}])
def test_invalid_limits(kwargs):
    with pytest.raises(engine.AndroidBackupError):
        engine.Limits(**kwargs)


@pytest.mark.parametrize("entrypoint", [engine.parse_header, engine.parse_backup, engine.inventory_tar])
def test_deterministic_fail_closed_mutations(entrypoint):
    rng = random.Random(0xAB2026)
    valid = tar(record()) if entrypoint is engine.inventory_tar else backup(tar(record()), compressed=False)
    fixtures = [b"", b"\xff" * 2048, None, "not bytes", [], 12]
    fixtures += [valid[:n] for n in [1, 14, 15, 16, 24, 25, 256, 511, 512, 1023, len(valid) - 1]]
    for _ in range(100):
        fixtures.append(rng.randbytes(rng.randrange(0, 2049)))
        mutated = bytearray(valid)
        mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
        fixtures.append(bytes(mutated))
    for fixture in fixtures:
        assert isinstance(engine.detect_backup(fixture), bool)
        try:
            entrypoint(fixture)
        except engine.AndroidBackupError:
            pass


def test_empty_tar_and_bytes_like_inputs():
    for fixture in (bytes(1024), bytearray(1024), memoryview(bytes(1024))):
        assert engine.inventory_tar(fixture)["members"] == []
    for bad in (None, "ANDROID BACKUP\n", 12, [], b"ANDROID BACKUP"):
        assert engine.detect_backup(bad) is False


def test_cli_guards_and_json(tmp_path, capsys, monkeypatch):
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main(["--unknown"]) == 2
    assert engine.main([str(tmp_path / "missing")]) == 2
    assert engine.main(["\x00"]) == 2
    fixture = tmp_path / "sample.ab"
    fixture.write_bytes(backup(tar(record())))
    capsys.readouterr()
    assert engine.main([str(fixture)]) == 0
    assert json.loads(capsys.readouterr().out)["inventory"]["members"][0]["size"] == 3
    assert engine.main([str(fixture), "--max-output", "1"]) == 2
    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", lambda *a, **k: (_ for _ in ()).throw(SystemExit("bad")))
    assert engine.main([]) == 2
