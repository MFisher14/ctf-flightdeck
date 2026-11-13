"""Independent SQLite/media vectors plus malformed-input contract tests."""
from __future__ import annotations

import hashlib
import inspect
import io
import json
from pathlib import Path
import random
import sqlite3
import struct

import pillow_heif
import pytest
from PIL import Image

import mobile2_ios_media as media
import mobile2_messenger_db as messenger


FIXTURES = Path(__file__).parent / "fixtures" / "meta_formats"
SECRET = "CSCTF{r3mob_row_value_must_stay_private}"


def _sqlite() -> tuple[bytes, dict[str, dict[str, object]]]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(
            "CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, text_data TEXT);"
            "CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);"
            "CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT);"
            "CREATE TABLE message_media(message_row_id INTEGER, file_path TEXT);"
        )
        connection.execute("INSERT INTO message(text_data) VALUES(?)", (SECRET,))
        connection.commit()
        expected = {}
        for (name,) in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
            quoted = name.replace('"', '""')
            columns = [row[1] for row in connection.execute(
                f'PRAGMA table_info("{quoted}")')]
            count = connection.execute(
                f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0]
            expected[name] = {"columns": columns, "row_count": count}
        return connection.serialize(), expected
    finally:
        connection.close()


def _ktx(payload: bytes, width: int, height: int) -> bytes:
    fields = (media.GL_UNSIGNED_BYTE, 1, media.GL_RGBA, media.GL_RGBA8,
              media.GL_RGBA, width, height, 0, 0, 1, 1, 0)
    return (media.KTX1_MAGIC + b"\x01\x02\x03\x04"
            + struct.pack("<12I", *fields)
            + struct.pack("<I", len(payload)) + payload
            + bytes((-len(payload)) % 4))


def _declared(error, call) -> None:
    try:
        result = call()
    except Exception as exc:
        assert type(exc) is error
    else:
        assert result is None or isinstance(result, dict)


def test_vector_lock_sqlite_schema_and_metadata_only_profile() -> None:
    raw, expected = _sqlite()
    schema = {name: {"columns": facts["columns"]} for name, facts in expected.items()}
    classification = messenger.classify_schema(schema)
    assert classification["kind"] == "whatsapp-android"
    assert classification["variant"] == "modern"

    report = messenger.profile_artifact(raw, filename="msgstore.db")
    assert report["status"] == "plaintext-sqlite"
    assert report["classification"]["kind"] == "whatsapp-android"
    actual = {item["name"]: item for item in report["tables"]}
    assert set(actual) == set(expected)
    for name, facts in expected.items():
        assert actual[name]["columns"] == facts["columns"]
        assert actual[name]["row_count"] == facts["row_count"]
    assert report["decryption_attempted"] is False
    assert report["message_values_reported"] is False
    assert SECRET not in json.dumps(report, sort_keys=True)


def test_encrypted_messenger_never_calls_plaintext_parser_or_decryptor(monkeypatch) -> None:
    calls: list[bytes] = []

    def forbidden(raw: bytes):
        calls.append(raw)
        raise AssertionError("encrypted artifact reached plaintext parser")

    monkeypatch.setattr(messenger.mobile_artifacts, "parse_sqlite", forbidden)
    sqlite_looking_ciphertext = messenger.SQLITE_MAGIC + b"ciphertext" * 32
    for suffix in ("crypt12", "crypt14", "crypt15", "CRYPT14"):
        report = messenger.profile_artifact(
            sqlite_looking_ciphertext, filename=f"msgstore.db.{suffix}"
        )
        assert report["status"] == "encrypted-backup"
        assert report["decryption_attempted"] is False
        assert report["tables"] == []
        assert "separate approved decryptor" in report["requires"]
    assert calls == []
    assert set(inspect.signature(messenger.profile_artifact).parameters) == {
        "data", "filename", "companions",
    }


def test_vector_lock_ktx_signal_and_real_heif_decoder() -> None:
    pixels = bytes((255, 0, 0, 255, 0, 255, 0, 255,
                    0, 0, 255, 255, 255, 255, 255, 128))
    raw = _ktx(pixels, 2, 2)
    oracle = Image.frombytes("RGBA", (2, 2), pixels)
    report = media.parse_ktx(raw)
    decoded = media.decode_ktx(raw)
    assert report["container"] == "ktx1"
    assert (report["width"], report["height"]) == oracle.size
    assert decoded["rgba"] == oracle.tobytes()
    assert [oracle.getpixel((x, y)) for y in range(2) for x in range(2)] == [
        (255, 0, 0, 255), (0, 255, 0, 255),
        (0, 0, 255, 255), (255, 255, 255, 128),
    ]

    heif_raw = (FIXTURES / "sample.heic").read_bytes()
    oracle_file = pillow_heif.open_heif(io.BytesIO(heif_raw), convert_hdr_to_8bit=True)
    oracle_rgba = oracle_file[0].to_pillow().convert("RGBA").tobytes()
    inspected = media.inspect_heif(heif_raw)
    actual = media.decode_heif(heif_raw)["images"][0]["rgba"]
    assert inspected["major_brand"] == "heic"
    assert inspected["category"] == "heic"
    assert actual == oracle_rgba
    assert hashlib.sha256(oracle_rgba).hexdigest() == (
        "ca24291d90498469cd9aba6f68de532f358ecccfc3c3d84dd4dd9353b2a2e7c9"
    )


def test_fail_closed_messenger_entrypoints(monkeypatch) -> None:
    valid, _ = _sqlite()
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x80
    corpus = [b"", random.Random(0x4D455353).randbytes(97), "💥".encode(),
              valid[:15], valid[:-1], bytes(flipped)]
    for raw in corpus:
        _declared(messenger.MessengerProfileError,
                  lambda raw=raw: messenger.profile_artifact(raw, filename="msgstore.db"))
    for tables in (None, [], {"x": None}, {"x": {"columns": [b"bad"]}}):
        _declared(messenger.MessengerProfileError,
                  lambda tables=tables: messenger.classify_schema(tables))
    released = memoryview(b"released")
    released.release()
    with pytest.raises(messenger.MessengerProfileError):
        messenger.profile_artifact(released)
    monkeypatch.setattr(messenger, "MAX_INPUT", 32)
    with pytest.raises(messenger.MessengerProfileError):
        messenger.profile_artifact(b"x" * 33)
    assert messenger.main([]) == 2
    assert messenger.main(["--not-an-option"]) == 2


def test_fail_closed_media_entrypoints(monkeypatch) -> None:
    ktx = _ktx(bytes((1, 2, 3, 4)), 1, 1)
    heif = (FIXTURES / "sample.heic").read_bytes()
    ktx_flipped = bytearray(ktx)
    ktx_flipped[40] ^= 0x80
    heif_flipped = bytearray(heif)
    heif_flipped[len(heif_flipped) // 2] ^= 0x80
    corpus = [b"", random.Random(0x4D454449).randbytes(101), "💥".encode(),
              ktx[:11], ktx[:-1], bytes(ktx_flipped),
              heif[:15], heif[:-1], bytes(heif_flipped)]
    released = memoryview(b"released")
    released.release()
    corpus.append(released)
    for raw in corpus:
        for parser in (media.parse_ktx, media.decode_ktx,
                       media.inspect_heif, media.decode_heif):
            _declared(media.Mobile2MediaError,
                      lambda parser=parser, raw=raw: parser(raw))
    monkeypatch.setattr(media, "MAX_INPUT", 32)
    for parser in (media.parse_ktx, media.decode_ktx, media.inspect_heif, media.decode_heif):
        with pytest.raises(media.Mobile2MediaError):
            parser(b"x" * 33)
    assert media.main([]) == 2
    assert media.main(["--not-an-option"]) == 2
