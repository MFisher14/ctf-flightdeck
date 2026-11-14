"""Oracle: PyCryptodome AES-GCM; SQLite producer; Chromium published framing.

No production encoder exists. Inputs come from the independent crypto library
and sqlite3, with host binding manually assembled per Chromium's schema v24.
"""
import base64
import hashlib
import json
import random
import sqlite3

import pytest
from Crypto.Cipher import AES

import foridepth_cookies as engine

KEY = bytes(range(32))
HOST = ".example.test"


def oracle_blob(value=b"CSCTF{modern_cookie}", *, host=HOST, version=24, tag=b"v20"):
    nonce = bytes(range(12))
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    payload = hashlib.sha256(host.encode()).digest() + value if version >= 24 else value
    ciphertext, auth = cipher.encrypt_and_digest(payload)
    return tag + nonce + ciphertext + auth


def database(rows, version="24"):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE meta(key TEXT, value TEXT)")
    connection.execute("INSERT INTO meta VALUES ('version', ?)", (version,))
    connection.execute("CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB)")
    connection.executemany("INSERT INTO cookies VALUES (?,?,?,?,?)", rows)
    connection.commit()
    data = connection.serialize()
    connection.close()
    return data


@pytest.mark.parametrize("tag", [b"v10", b"v11", b"v20"])
@pytest.mark.parametrize("version", [23, 24])
@pytest.mark.parametrize("value", [b"", b"CSCTF{oracle}", b"\xff\x00binary"])
def test_independent_aes_oracle(tag, version, value):
    assert engine.decrypt_cookie(oracle_blob(value, tag=tag, version=version), KEY,
        host_key=HOST, schema_version=version) == value


def test_authentication_and_binding():
    blob = oracle_blob()
    for position in (3, 15, len(blob) - 1):
        corrupt = bytearray(blob)
        corrupt[position] ^= 1
        with pytest.raises(engine.ForidepthCookieError):
            engine.decrypt_cookie(bytes(corrupt), KEY, host_key=HOST, schema_version=24)
    for kwargs in ({"host_key": "example.test", "schema_version": 24},
                   {"host_key": HOST, "schema_version": 25}):
        with pytest.raises(engine.ForidepthCookieError):
            engine.decrypt_cookie(blob, KEY, **kwargs)
    with pytest.raises(engine.ForidepthCookieError):
        engine.decrypt_cookie(blob, bytes(32), host_key=HOST, schema_version=24)
    with pytest.raises(engine.ForidepthCookieError):
        engine.decrypt_cookie(oracle_blob(version=23), KEY, host_key=HOST, schema_version=24)


def test_schema_is_independent_of_envelope_tag():
    # A v20 envelope can predate schema 24. Do not blindly discard 32 bytes.
    value = b"x" * 64
    assert engine.decrypt_cookie(oracle_blob(value, version=23), KEY,
        host_key=HOST, schema_version=23) == value


def test_sqlite_reader_and_separate_keys():
    data = database([(HOST, "session", "/", "", oracle_blob()),
                     (HOST, "legacy", "/", "", oracle_blob(tag=b"v10")),
                     (HOST, "plain", "/", "hello", b"")])
    rows = engine.read_cookie_database(data, v20_key=KEY)["cookies"]
    assert rows[0]["value"] == "CSCTF{modern_cookie}"
    assert rows[0]["authenticated"] and rows[0]["host_bound"]
    assert rows[1]["status"] == "locked" and rows[1]["value"] is None
    assert rows[2]["value"] == "hello" and not rows[2]["authenticated"]
    assert engine.read_cookie_database(data, v20_key=KEY, legacy_key=KEY)["cookies"][1]["status"] == "decrypted"


def test_whole_result_rejected_for_bad_binding():
    data = database([(HOST, "one", "/", "", oracle_blob()),
                     ("wrong.test", "two", "/", "", oracle_blob())])
    with pytest.raises(engine.ForidepthCookieError):
        engine.read_cookie_database(data, v20_key=KEY)


def test_committed_wal_from_sqlite_library(tmp_path):
    path = tmp_path / "Cookies"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE meta(key TEXT, value TEXT)")
    connection.execute("INSERT INTO meta VALUES ('version', '24')")
    connection.execute("CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB)")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("INSERT INTO cookies VALUES (?, 'session', '/', '', ?)", (HOST, oracle_blob()))
    connection.commit()
    data = path.read_bytes()
    wal = path.with_name("Cookies-wal").read_bytes()
    connection.close()
    assert engine.read_cookie_database(data)["cookies"] == []
    result = engine.read_cookie_database(data, wal=wal, v20_key=KEY)
    assert result["wal_frames"] > 0
    assert result["cookies"][0]["value"] == "CSCTF{modern_cookie}"
    damaged = wal[:-1] + bytes([wal[-1] ^ 1])
    with pytest.raises(engine.ForidepthCookieError):
        engine.read_cookie_database(data, wal=damaged, v20_key=KEY)


def test_bad_optional_metadata_and_duplicate_version():
    for statement in ("ALTER TABLE cookies ADD COLUMN creation_utc BLOB",
                      "INSERT INTO meta VALUES ('version', '23')"):
        connection = sqlite3.connect(":memory:")
        connection.deserialize(database([(HOST, "plain", "/", "hello", b"")]))
        connection.execute(statement)
        connection.commit()
        data = connection.serialize()
        connection.close()
        with pytest.raises(engine.ForidepthCookieError):
            engine.read_cookie_database(data)


@pytest.mark.parametrize("statement", [
    "ALTER TABLE cookies ADD COLUMN rowid BLOB",
    "UPDATE cookies SET value=CAST(X'80' AS TEXT)",
    "UPDATE cookies SET host_key=CAST(X'80' AS TEXT)",
    "UPDATE cookies SET value='replacement \ufffd'",
])
def test_shared_reader_does_not_leak_rowid_or_replace_evidence(statement, tmp_path):
    connection = sqlite3.connect(":memory:")
    connection.deserialize(database([(HOST, "plain", "/", "hello", b"")]))
    connection.execute(statement)
    connection.commit()
    data = connection.serialize()
    connection.close()
    with pytest.raises(engine.ForidepthCookieError):
        engine.read_cookie_database(data)
    path = tmp_path / "Cookies"
    path.write_bytes(data)
    assert engine.main(["database", str(path)]) == 2


@pytest.mark.parametrize("rows,version", [
    ([(HOST, "both", "/", "ambiguous", oracle_blob())], "24"),
    ([(HOST, "badtype", "/", "", "text-not-blob")], "24"),
    ([(HOST, "missing", "/", "", b"")], "25"),
    ([(HOST, "badversion", "/", "", b"")], "24.0"),
])
def test_invalid_database(rows, version):
    with pytest.raises(engine.ForidepthCookieError):
        engine.read_cookie_database(database(rows, version))


def test_binary_cookie_json():
    data = database([(HOST, "binary", "/", "", oracle_blob(b"\xff\x00"))])
    row = engine.read_cookie_database(data, v20_key=KEY)["cookies"][0]
    assert row["value_encoding"] == "base64"
    assert base64.b64decode(row["value"]) == b"\xff\x00"


def test_local_state_identifies_wrappers_without_unwrapping():
    raw = json.dumps({"os_crypt": {
        "encrypted_key": base64.b64encode(b"DPAPIwrapped").decode(),
        "app_bound_encrypted_key": base64.b64encode(b"APPBwrapped").decode()}}).encode()
    result = engine.inspect_local_state(raw)
    assert result["app_bound_encrypted_key"]["wrapper"] == "APPB"
    assert "wrapped" not in json.dumps(result).replace("wrapped_bytes", "")
    for invalid in (b"{}", b'[]', b'{"os_crypt":{},"os_crypt":{}}',
                    b'{"os_crypt":{"encrypted_key":"!"}}'):
        with pytest.raises(engine.ForidepthCookieError):
            engine.inspect_local_state(invalid)


def test_error_contract_and_truncations():
    for value in (None, [], {}, 42, "text", bytearray(b"v20")):
        for fn in (engine.inspect_local_state, engine.read_cookie_database):
            with pytest.raises(engine.ForidepthCookieError):
                fn(value)
        with pytest.raises(engine.ForidepthCookieError):
            engine.decrypt_cookie(value, KEY, host_key=HOST, schema_version=24)
    blob = oracle_blob()
    for length in range(len(blob)):
        with pytest.raises(engine.ForidepthCookieError):
            engine.decrypt_cookie(blob[:length], KEY, host_key=HOST, schema_version=24)
    rng = random.Random(732)
    for _ in range(60):
        with pytest.raises(engine.ForidepthCookieError):
            engine.read_cookie_database(rng.randbytes(rng.randrange(1024)))
    with pytest.raises(engine.ForidepthCookieError):
        engine.decrypt_cookie(blob, KEY, host_key="\ud800", schema_version=24)


def test_cli(tmp_path, capsys):
    artifact = tmp_path / "cookie.bin"
    artifact.write_bytes(oracle_blob())
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(KEY)
    assert engine.main(["blob", str(artifact), "--key-file", str(keyfile),
                        "--host", HOST, "--schema-version", "24"]) == 0
    assert json.loads(capsys.readouterr().out)["value"] == "CSCTF{modern_cookie}"
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main(["local-state", str(tmp_path / "absent")]) == 2


def test_cli_noninteger_system_exit(monkeypatch):
    def exit_string(*args, **kwargs):
        raise SystemExit("bad")
    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", exit_string)
    assert engine.main([]) == 2
