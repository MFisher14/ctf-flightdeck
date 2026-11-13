"""Independent tests for the metadata-only mobile messenger profiler.

SQLite fixtures and expected schemas/counts are produced by the stdlib SQLite
library, not by the engine's byte parser.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

import mobile2_messenger_db as messenger


SECRET = "CSCTF{database_row_values_must_not_escape}"


def _database(schema: str, insert: str | None = None) -> tuple[bytes, dict[str, dict[str, object]]]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(schema)
        if insert is not None:
            connection.execute(insert, (SECRET,))
        connection.commit()
        expected: dict[str, dict[str, object]] = {}
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for name in names:
            quoted = name.replace('"', '""')
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")')]
            count = connection.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0]
            expected[name] = {"columns": columns, "row_count": count}
        return connection.serialize(), expected
    finally:
        connection.close()


SCHEMAS = [
    pytest.param(
        """
        CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, text_data TEXT);
        CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
        CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT);
        CREATE TABLE message_media(message_row_id INTEGER, file_path TEXT);
        """,
        "INSERT INTO message(chat_row_id, text_data) VALUES(1, ?)",
        "whatsapp-android", "modern", id="whatsapp-android-modern",
    ),
    pytest.param(
        """
        CREATE TABLE messages(_id INTEGER PRIMARY KEY, key_remote_jid TEXT,
                              key_from_me INTEGER, data TEXT, timestamp INTEGER);
        CREATE TABLE chat_list(_id INTEGER PRIMARY KEY, key_remote_jid TEXT);
        """,
        "INSERT INTO messages(key_remote_jid,key_from_me,data,timestamp) VALUES('x',0,?,1)",
        "whatsapp-android", "legacy", id="whatsapp-android-legacy",
    ),
    pytest.param(
        """
        CREATE TABLE ZWAMESSAGE(Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT, ZCHATSESSION INTEGER);
        CREATE TABLE ZWACHATSESSION(Z_PK INTEGER PRIMARY KEY, ZPARTNERNAME TEXT);
        CREATE TABLE ZWAMEDIAITEM(Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER);
        CREATE TABLE Z_METADATA(Z_VERSION INTEGER);
        CREATE TABLE Z_PRIMARYKEY(Z_ENT INTEGER, Z_NAME TEXT, Z_MAX INTEGER);
        """,
        "INSERT INTO ZWAMESSAGE(ZTEXT) VALUES(?)",
        "whatsapp-ios", "chatstorage", id="whatsapp-ios",
    ),
    pytest.param(
        """
        CREATE TABLE message(_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT);
        CREATE TABLE thread(_id INTEGER PRIMARY KEY, recipient_id INTEGER);
        CREATE TABLE recipient(_id INTEGER PRIMARY KEY, e164 TEXT);
        CREATE TABLE attachment(_id INTEGER PRIMARY KEY, message_id INTEGER);
        """,
        "INSERT INTO message(body) VALUES(?)",
        "signal-android", "current", id="signal-android-current",
    ),
    pytest.param(
        """
        CREATE TABLE sms(_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT);
        CREATE TABLE mms(_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT);
        CREATE TABLE thread(_id INTEGER PRIMARY KEY, recipient_id INTEGER);
        """,
        "INSERT INTO sms(body) VALUES(?)",
        "signal-android", "legacy-sms-mms", id="signal-android-legacy",
    ),
    pytest.param(
        """
        CREATE TABLE model_TSInteraction(id INTEGER PRIMARY KEY, body TEXT);
        CREATE TABLE model_TSThread(id INTEGER PRIMARY KEY, uniqueId TEXT);
        CREATE TABLE model_SignalRecipient(id INTEGER PRIMARY KEY, recipientUUID TEXT);
        CREATE TABLE grdb_migrations(identifier TEXT PRIMARY KEY);
        CREATE TABLE Attachment(id INTEGER PRIMARY KEY, mimeType TEXT);
        CREATE TABLE MessageAttachmentReference(ownerRowId INTEGER, attachmentRowId INTEGER);
        """,
        "INSERT INTO model_TSInteraction(body) VALUES(?)",
        "signal-ios", "grdb", id="signal-ios",
    ),
]


@pytest.mark.parametrize("schema,insert,kind,variant", SCHEMAS)
def test_real_sqlite_schema_families_are_metadata_only(schema, insert, kind, variant):
    raw, oracle = _database(schema, insert)
    report = messenger.profile_artifact(raw, filename="fixture.db")

    assert report["status"] == "plaintext-sqlite"
    assert report["classification"]["kind"] == kind
    assert report["classification"]["variant"] == variant
    assert report["classification"]["confidence"] == "high"
    assert report["message_values_reported"] is False
    assert report["decryption_attempted"] is False

    actual = {item["name"]: item for item in report["tables"]}
    assert set(actual) == set(oracle)
    for name, expected in oracle.items():
        assert actual[name]["columns"] == expected["columns"]
        assert actual[name]["row_count"] == expected["row_count"]

    # The byte parser necessarily sees the rows to count them, but the profiler's
    # public result must never carry their values.
    assert SECRET not in json.dumps(report, sort_keys=True)


def test_current_signal_message_table_is_not_whatsapp_evidence():
    raw, _ = _database(
        """
        CREATE TABLE message(_id INTEGER, body TEXT);
        CREATE TABLE thread(_id INTEGER);
        CREATE TABLE recipient(_id INTEGER);
        CREATE TABLE attachment(_id INTEGER);
        """)
    classification = messenger.profile_artifact(raw, filename="signal.db")["classification"]
    assert classification["kind"] == "signal-android"
    assert not any(item["kind"].startswith("whatsapp") for item in classification["candidates"])


def test_complete_competing_schemas_are_reported_ambiguous():
    raw, _ = _database(
        """
        CREATE TABLE message(_id INTEGER);
        CREATE TABLE chat(_id INTEGER);
        CREATE TABLE jid(_id INTEGER);
        CREATE TABLE thread(_id INTEGER);
        CREATE TABLE recipient(_id INTEGER);
        CREATE TABLE attachment(_id INTEGER);
        """)
    classification = messenger.profile_artifact(raw, filename="combined.db")["classification"]
    assert classification["kind"] == "ambiguous"
    assert {item["kind"] for item in classification["candidates"]} == {
        "signal-android", "whatsapp-android"}


@pytest.mark.parametrize("suffix", ["crypt12", "crypt14", "crypt15"])
def test_whatsapp_crypt_backups_decline_without_a_key(suffix):
    report = messenger.profile_artifact(b"encrypted backup bytes", filename=f"msgstore.db.{suffix}")
    assert report["status"] == "encrypted-backup"
    assert report["classification"]["kind"] == "whatsapp-android-backup"
    assert report["classification"]["variant"] == suffix
    assert report["tables"] == []
    assert report["decryption_attempted"] is False
    assert "key" in report["requires"].lower()


def test_opaque_and_plaintext_header_ambiguity_are_explicit():
    opaque = messenger.profile_artifact(b"not sqlite ciphertext", filename="signal.db")
    assert opaque["status"] == "opaque"
    assert opaque["classification"]["kind"] == "signal-android-candidate"
    assert opaque["tables"] == [] and opaque["decryption_attempted"] is False

    malformed = messenger.profile_artifact(
        b"SQLite format 3\x00" + b"\x00" * 84, filename="signal.sqlite")
    assert malformed["status"] == "opaque-or-malformed"
    assert malformed["classification"]["kind"] == "signal-ios-candidate"
    assert "indistinguishable" in malformed["reason"]


def test_wal_and_shm_companions_are_presence_only():
    raw, _ = _database("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)")
    report = messenger.profile_artifact(
        raw,
        filename="/evidence/signal.db",
        companions=[
            "/evidence/signal.db-wal",
            "/evidence/signal.db-shm",
            "/evidence/other.db-wal",
        ],
    )
    assert report["sidecars"]["wal_present"] is True
    assert report["sidecars"]["shm_present"] is True
    matches = {item["path"]: item["matches_main"] for item in report["sidecars"]["artifacts"]}
    assert matches["/evidence/signal.db-wal"] is True
    assert matches["/evidence/signal.db-shm"] is True
    assert matches["/evidence/other.db-wal"] is False


def test_declared_exception_contract_for_invalid_python_inputs():
    invalid_calls = [
        lambda: messenger.profile_artifact(None),
        lambda: messenger.profile_artifact(b""),
        lambda: messenger.profile_artifact(b"x", filename=b"bytes-path"),
        lambda: messenger.profile_artifact(b"x", companions="one-path"),
        lambda: messenger.classify_schema([]),
        lambda: messenger.classify_schema({"t": {"columns": "not-a-list"}}),
        lambda: messenger.classify_schema({"T": {"columns": []}, "t": {"columns": []}}),
        lambda: messenger.classify_schema({"t": {"columns": ["x"] * (messenger.MAX_COLUMNS + 1)}}),
    ]
    for call in invalid_calls:
        with pytest.raises(messenger.MessengerProfileError):
            call()


def test_malformed_byte_corpus_never_leaks_stdlib_exceptions():
    raw, _ = _database(
        "CREATE TABLE message(_id INTEGER); CREATE TABLE chat(_id INTEGER); CREATE TABLE jid(_id INTEGER)")
    samples = [b"x", b"\xff" * 31]
    samples.extend(raw[:size] for size in (1, 4, 15, 16, 31, 99, len(raw) // 2, len(raw) - 1))
    for offset in (0, 15, 16, 19, 55, len(raw) - 1):
        changed = bytearray(raw)
        changed[offset] ^= 0x80
        samples.append(bytes(changed))
    for sample in samples:
        try:
            result = messenger.profile_artifact(sample, filename="msgstore.db")
        except Exception as exc:  # pragma: no cover - assertion reports the leaked class
            assert isinstance(exc, messenger.MessengerProfileError)
        else:
            assert isinstance(result, dict)
            assert result["status"] in {"plaintext-sqlite", "opaque", "opaque-or-malformed"}


def test_guarded_cli_success_help_and_errors(tmp_path, capsys):
    assert messenger.main(["--help"]) == 0
    capsys.readouterr()
    assert messenger.main([]) == 2
    assert messenger.main(["--unknown"]) == 2
    capsys.readouterr()

    raw, _ = _database(
        "CREATE TABLE message(_id INTEGER); CREATE TABLE chat(_id INTEGER); CREATE TABLE jid(_id INTEGER)")
    database = tmp_path / "msgstore.db"
    database.write_bytes(raw)
    assert messenger.main([
        str(database),
        "--companion", str(database) + "-wal",
        "--companion", str(database) + "-shm",
    ]) == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["classification"]["kind"] == "whatsapp-android"
    assert output["sidecars"]["wal_present"] is True
    assert output["sidecars"]["shm_present"] is True

    assert messenger.main([str(tmp_path / "missing.db")]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
