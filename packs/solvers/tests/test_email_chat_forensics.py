from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path

import pytest

import email_chat_forensics as messaging

from email_chat_forensics import (
    build_email_threads,
    decode_chat_database,
    decode_email_artifact,
)


def _mail(message_id: str, *, subject: str = "Evidence", parent: str | None = None,
          references: tuple[str, ...] = (), attachment: bytes | None = None,
          close: bool = True, corrupt_base64: bool = False) -> bytes:
    headers = [
        "From: Alice <alice@example.invalid>",
        "To: Bob <bob@example.invalid>",
        "Date: Tue, 14 Nov 2023 22:13:20 +0000",
        f"Message-ID: <{message_id}>",
        f"Subject: {subject}",
        "MIME-Version: 1.0",
    ]
    if parent:
        headers.append(f"In-Reply-To: <{parent}>")
    if references:
        headers.append("References: " + " ".join(f"<{value}>" for value in references))
    if attachment is None:
        headers.append("Content-Type: text/plain; charset=utf-8")
        return ("\r\n".join(headers) + "\r\n\r\nbody\r\n").encode()
    boundary = "r5e-boundary"
    headers.append(f'Content-Type: multipart/related; boundary="{boundary}"')
    encoded = base64.b64encode(attachment).decode()
    if corrupt_base64:
        encoded = encoded[:-2] + "**"
    parts = [
        "\r\n".join(headers),
        "",
        f"--{boundary}",
        "Content-Type: text/html; charset=utf-8",
        "",
        '<p>inline <img src="cid:evidence-image"></p>',
        f"--{boundary}",
        "Content-Type: image/png",
        "Content-Transfer-Encoding: base64",
        'Content-Disposition: inline; filename="evidence.png"',
        "Content-ID: <evidence-image>",
        "",
        encoded,
    ]
    if close:
        parts += [f"--{boundary}--", ""]
    return "\r\n".join(parts).encode()


def test_exact_mime_attachment_inline_object_and_corrupt_declines():
    payload = b"\x89PNG\r\n\x1a\nstrict-inline"
    raw = _mail("root@example.invalid", attachment=payload)
    artifact = decode_email_artifact(raw)
    assert artifact is not None and artifact.kind == "eml"
    message = artifact.messages[0]
    assert message.message_id == "root@example.invalid"
    assert message.date == "2023-11-14T22:13:20+00:00"
    assert len(message.objects) == 1
    inline = message.objects[0]
    assert inline.inline and inline.content_id == "evidence-image"
    assert inline.data == payload
    assert inline.sha256 == hashlib.sha256(payload).hexdigest()

    assert decode_email_artifact(_mail("cut@example.invalid", attachment=payload, close=False)) is None
    assert decode_email_artifact(_mail("bad@example.invalid", attachment=payload,
                                       corrupt_base64=True)) is None
    assert decode_email_artifact(b"From: x\r\nno blank separator") is None


def test_rfc_message_id_threading_and_ambiguity_declines():
    root = _mail("root@example.invalid", subject="Root")
    reply = _mail("reply@example.invalid", subject="Re: Root", parent="root@example.invalid",
                  references=("root@example.invalid",))
    leaf = _mail("leaf@example.invalid", subject="Re: Root", parent="reply@example.invalid",
                 references=("root@example.invalid", "reply@example.invalid"))
    threads = build_email_threads({"root.eml": root, "reply.eml": reply, "leaf.eml": leaf})
    assert threads is not None and len(threads) == 1
    assert threads[0].root_id == "root@example.invalid"
    assert threads[0].edges == (
        ("root@example.invalid", "reply@example.invalid"),
        ("reply@example.invalid", "leaf@example.invalid"),
    )

    assert build_email_threads([root, root]) is None
    ambiguous = leaf.replace(
        b"In-Reply-To: <reply@example.invalid>",
        b"In-Reply-To: <reply@example.invalid> <root@example.invalid>",
    )
    assert build_email_threads([root, reply, ambiguous]) is None
    cyclic_a = _mail("a@example.invalid", parent="b@example.invalid")
    cyclic_b = _mail("b@example.invalid", parent="a@example.invalid")
    assert build_email_threads([cyclic_a, cyclic_b]) is None

    external_parent = _mail("external@example.invalid", parent="outside@example.invalid",
                            references=("root@example.invalid", "outside@example.invalid"))
    threads = build_email_threads([root, external_parent])
    assert threads is not None and threads[0].edges == (
        ("root@example.invalid", "external@example.invalid"),
    )


def _sqlite(tmp_path: Path, schema: str, rows: str, *, wal: bool = False):
    path = tmp_path / ("chat-wal.db" if wal else "chat.db")
    connection = sqlite3.connect(path)
    if wal:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    connection.executescript(schema)
    connection.commit()
    if wal:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.executescript(rows)
    connection.commit()
    raw = path.read_bytes()
    side_wal = Path(str(path) + "-wal").read_bytes() if wal else None
    side_shm = Path(str(path) + "-shm").read_bytes() if wal else None
    connection.close()
    return raw, side_wal, side_shm


def test_generic_chat_database_wal_threads_and_blob_attachment(tmp_path):
    payload = b"chat attachment bytes"
    digest = hashlib.sha256(payload).hexdigest()
    schema = """
        CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT);
        CREATE TABLE messages(id INTEGER PRIMARY KEY, thread_id INTEGER, sender TEXT,
                              body TEXT, timestamp_ms INTEGER, from_me INTEGER);
        CREATE TABLE attachments(id INTEGER PRIMARY KEY, message_id INTEGER, filename TEXT,
                                 mime TEXT, data BLOB, sha256 TEXT);
    """
    rows = f"""
        INSERT INTO threads VALUES(7, 'Incident');
        INSERT INTO messages VALUES(11, 7, 'alice', 'hello', 1700000000000, 0);
        INSERT INTO messages VALUES(12, 7, 'me', 'received', 1700000001000, 1);
        INSERT INTO attachments VALUES(21, 12, 'proof.bin', 'application/octet-stream',
                                       x'{payload.hex()}', '{digest}');
    """
    raw, wal, shm = _sqlite(tmp_path, schema, rows, wal=True)
    archive = decode_chat_database(raw, wal=wal, shm=shm)
    assert archive is not None and archive.schema == "generic_chat"
    assert archive.threads == (("7", "Incident"),)
    assert [message.text for message in archive.messages] == ["hello", "received"]
    assert archive.messages[1].from_me is True
    assert archive.attachments[0].data == payload
    assert archive.attachments[0].sha256 == digest
    assert archive.wal_frames >= 1

    damaged = bytearray(wal)
    damaged[-5] ^= 1
    assert decode_chat_database(raw, wal=damaged) is None
    assert decode_chat_database(raw, wal=wal[:-1]) is None


def test_chat_attachment_declared_digest_must_match(tmp_path):
    schema = """
        CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT);
        CREATE TABLE messages(id INTEGER PRIMARY KEY, thread_id INTEGER, sender TEXT,
                              body TEXT, timestamp_ms INTEGER, from_me INTEGER);
        CREATE TABLE attachments(id INTEGER PRIMARY KEY, message_id INTEGER, filename TEXT,
                                 mime TEXT, data BLOB, sha256 TEXT);
    """
    rows = """
        INSERT INTO threads VALUES(1, 'x');
        INSERT INTO messages VALUES(1, 1, 'x', 'x', 1700000000000, 0);
        INSERT INTO attachments VALUES(1, 1, 'x.bin', 'application/octet-stream', x'0102', 'wrong');
    """
    raw, _, _ = _sqlite(tmp_path, schema, rows)
    assert decode_chat_database(raw) is None


def test_ios_messages_and_only_explicit_supplied_attachment(tmp_path):
    schema = """
        CREATE TABLE handle(id TEXT);
        CREATE TABLE chat(display_name TEXT, chat_identifier TEXT);
        CREATE TABLE message(text TEXT, is_from_me INTEGER, date INTEGER, handle_id INTEGER);
        CREATE TABLE chat_message_join(chat_id INTEGER, message_id INTEGER);
        CREATE TABLE attachment(filename TEXT, mime_type TEXT, total_bytes INTEGER);
        CREATE TABLE message_attachment_join(message_id INTEGER, attachment_id INTEGER);
    """
    rows = """
        INSERT INTO handle(rowid,id) VALUES(2,'+15551234567');
        INSERT INTO chat(rowid,display_name,chat_identifier) VALUES(3,'Evidence chat','chat-3');
        INSERT INTO message(rowid,text,is_from_me,date,handle_id)
            VALUES(5,'preserved message',0,700000000000000000,2);
        INSERT INTO chat_message_join VALUES(3,5);
        INSERT INTO attachment(rowid,filename,mime_type,total_bytes)
            VALUES(8,'Media/proof.bin','application/octet-stream',5);
        INSERT INTO message_attachment_join VALUES(5,8);
    """
    raw, _, _ = _sqlite(tmp_path, schema, rows)
    no_media = decode_chat_database(raw)
    assert no_media is not None and no_media.schema == "ios_sms" and not no_media.attachments
    archive = decode_chat_database(raw, sidecars={"Media/proof.bin": b"proof"})
    assert archive is not None
    assert archive.messages[0].sender == "+15551234567"
    assert archive.messages[0].thread_id == "3"
    assert archive.attachments[0].data == b"proof"
    assert decode_chat_database(raw, sidecars={"Media/proof.bin": b"tiny"}) is None


@pytest.mark.parametrize("bad", [None, True, 1, "mail", object(), [], {}])
def test_public_email_and_chat_decoders_decline_wrong_types(bad):
    assert decode_email_artifact(bad) is None
    assert build_email_threads(bad) is None
    assert decode_chat_database(bad) is None


def test_email_and_chat_resource_caps_decline_without_prefixes(tmp_path, monkeypatch):
    raw_mail = _mail("cap@example.invalid", attachment=b"12345")
    monkeypatch.setattr(messaging, "MAX_ATTACHMENT", 4)
    assert decode_email_artifact(raw_mail) is None

    schema = """
        CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT);
        CREATE TABLE messages(id INTEGER PRIMARY KEY, thread_id INTEGER, sender TEXT,
                              body TEXT, timestamp_ms INTEGER, from_me INTEGER);
    """
    rows = """
        INSERT INTO threads VALUES(1, 'cap');
        INSERT INTO messages VALUES(1,1,'a','one',1700000000000,0);
        INSERT INTO messages VALUES(2,1,'b','two',1700000000001,0);
    """
    raw, _, _ = _sqlite(tmp_path, schema, rows)
    monkeypatch.setattr(messaging, "MAX_CHAT_ROWS", 2)
    assert decode_chat_database(raw) is None
