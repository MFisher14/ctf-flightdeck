"""Independent vector locks and fail-closed fuzz for maildepth_archives."""
from __future__ import annotations

from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
import hashlib
import io
import json
import mailbox
import math
import random

import extract_msg
import olefile
import pytest

import maildepth_archives as mail
from test_maildepth_archives import (
    FakeFolder,
    FakeMessage,
    FakePffModule,
    make_msg,
    make_pff,
)


def _mbox() -> bytes:
    message = EmailMessage(policy=policy.default)
    message["From"] = "Alice <alice@example.invalid>"
    message["To"] = "Bob <bob@example.invalid>"
    message["Subject"] = "Route ☃"
    message["Date"] = "Fri, 06 Nov 2026 13:00:00 +0000"
    message["Message-ID"] = "<route-1@example.invalid>"
    message.set_content("known body CSCTF{r3mob_mbox_vector}")
    body = message.as_bytes(policy=policy.default).replace(b"\r\n", b"\n")
    return (b"From alice@example.invalid Fri Nov  6 13:00:00 2026\n"
            + body.rstrip(b"\n") + b"\n\n")


def _slack() -> dict[str, object]:
    return {
        "users.json": [{"id": "U1", "name": "alice"}],
        "channels.json": [{"id": "C1", "name": "dispatch", "members": ["U1"]}],
        "dispatch/2026-11-06.json": [{
            "type": "message", "user": "U1", "ts": "1793970000.000001",
            "text": "CSCTF{r3mob_slack_vector}",
        }],
    }


def _discord() -> dict[str, object]:
    return {"messages.json": [{
        "ID": "111111111111111111",
        "Timestamp": "2026-11-06T13:00:00+00:00",
        "Contents": "CSCTF{r3mob_discord_vector}", "Attachments": [],
    }]}


def _teams() -> bytes:
    return json.dumps({"value": [{
        "id": "teams-1", "createdDateTime": "2026-11-06T13:00:00Z",
        "lastModifiedDateTime": "2026-11-06T13:00:00Z",
        "lastEditedDateTime": None, "deletedDateTime": None,
        "chatId": "chat-1", "messageType": "message",
        "from": {"user": {"id": "aad-1", "displayName": "Alice"}},
        "body": {"contentType": "text", "content": "CSCTF{r3mob_teams_vector}"},
    }]}).encode()


def _declared(call, result_types=(dict, str)) -> None:
    try:
        result = call()
    except Exception as exc:
        assert type(exc) is mail.MailDepthError
    else:
        assert result is None or isinstance(result, result_types)


def test_vector_lock_msg_and_mbox_against_real_readers(tmp_path) -> None:
    msg_raw = make_msg()  # hand-built MS-CFB fixture, not engine output
    with olefile.OleFileIO(io.BytesIO(msg_raw)) as compound:
        assert ["__substg1.0_0037001F"] in compound.listdir()
    oracle = extract_msg.openMsg(io.BytesIO(msg_raw))
    try:
        expected_subject = oracle.subject.rstrip("\0")
        expected_body = oracle.body.rstrip("\0")
        expected_attachment = oracle.attachments[0].data
    finally:
        oracle.close()
    actual = mail.analyze_msg(msg_raw, "known.msg")["messages"][0]
    assert actual["subject"] == expected_subject == "MSG vector"
    assert actual["bodies"] == [["text/plain", expected_body]]
    assert actual["objects"][0]["data"] == expected_attachment
    assert mail.analyze_bytes(msg_raw, name="known.msg")["format"] == "msg"

    raw = _mbox()
    path = tmp_path / "known.mbox"
    path.write_bytes(raw)
    box = mailbox.mbox(path, create=False)
    try:
        expected = next(iter(box))
        expected_id = str(expected["Message-ID"])[1:-1]
        expected_subject = str(make_header(decode_header(str(expected["Subject"]))))
        expected_body = expected.get_payload()
    finally:
        box.close()
    result = mail.analyze_mbox(raw, "known.mbox")
    message = result["messages"][0]
    assert message["message_id"] == expected_id == "route-1@example.invalid"
    assert message["subject"] == expected_subject == "Route ☃"
    assert message["bodies"] == [["text/plain", expected_body]]
    assert mail.analyze_path(path)["threads"][0]["root_id"] == expected_id


def test_vector_lock_pff_chat_and_render_boundaries(tmp_path) -> None:
    raw = make_pff(b"SM", 23)  # published 512-byte NDB layout fixture
    profile = mail.inspect_pff(raw, "known.pst")
    assert profile["ndb_version"] == 23
    assert profile["trees"]["nbt"]["entries"][0]["nid"] == 0x21
    assert profile["trees"]["bbt"]["entries"][0]["file_offset"] == 2048

    root = FakeFolder("Root", messages=(FakeMessage(),))
    store = mail.extract_pff_store(root)
    assert store["counts"]["message_count"] == 1
    assert store["counts"]["attachment_count"] == 1
    path = tmp_path / "known.pst"
    path.write_bytes(raw)
    assert mail.analyze_pff_path(path, pypff_module=FakePffModule(root))["backend"] == "pypff"

    slack = mail.parse_slack_export(_slack())
    discord = mail.parse_discord_export(_discord())
    teams = mail.parse_teams_export(_teams())
    assert slack["messages"][0]["created"] == "2026-11-06T13:00:00.000001Z"
    assert slack["messages"][0]["flags"] == ["CSCTF{r3mob_slack_vector}"]
    assert discord["messages"][0]["id"] == "111111111111111111"
    assert discord["messages"][0]["flags"] == ["CSCTF{r3mob_discord_vector}"]
    assert teams["messages"][0]["flags"] == ["CSCTF{r3mob_teams_vector}"]
    assert mail.parse_chat_export(_slack(), platform="auto")["platform"] == "slack"
    assert mail.analyze_bytes(_teams(), name="teams.json")["platform"] == "teams"

    blob = b"abc"
    expected = json.dumps({
        "data": {"size": 3, "sha256": hashlib.sha256(blob).hexdigest()}
    }, sort_keys=True, ensure_ascii=False)
    assert mail.render_json({"data": blob}) == expected
    included = json.loads(mail.render_json({"data": blob}, include_bytes=True))
    assert included["data"]["base64"] == "YWJj"


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_render_json_rejects_non_finite_values(value) -> None:
    with pytest.raises(mail.MailDepthError):
        mail.render_json(value)


def test_render_json_rejects_key_stringification_collisions() -> None:
    with pytest.raises(mail.MailDepthError):
        mail.render_json({1: "integer", "1": "text"})


def test_fail_closed_all_mail_public_boundaries(tmp_path, monkeypatch) -> None:
    valid_msg, valid_mbox = make_msg(), _mbox()
    flipped = bytearray(valid_msg)
    flipped[len(flipped) // 2] ^= 0x80
    corpus = [b"", b"\xff" * 17, "💥".encode(), valid_msg[:31],
              valid_mbox[:-1], bytes(flipped)]
    corpus.extend(random.Random(0x52334D4F42).randbytes(n) for n in (1, 7, 63))
    for raw in corpus:
        calls = (
            lambda: mail.inspect_pff(raw, "fuzz.pst"),
            lambda: mail.extract_pff_store(raw),
            lambda: mail.analyze_msg(raw, "fuzz.msg"),
            lambda: mail.analyze_mbox(raw, "fuzz.mbox"),
            lambda: mail.parse_slack_export(raw),
            lambda: mail.parse_discord_export(raw),
            lambda: mail.parse_teams_export(raw),
            lambda: mail.parse_chat_export(raw),
            lambda: mail.analyze_bytes(raw, name="fuzz.bin"),
        )
        for call in calls:
            _declared(call)

    released = memoryview(b"released")
    released.release()
    for bad in (None, "💥", released, object()):
        _declared(lambda bad=bad: mail.analyze_bytes(bad, name="bad"))
        _declared(lambda bad=bad: mail.extract_pff_store(bad))
    cycle: list[object] = []
    cycle.append(cycle)
    _declared(lambda: mail.render_json(cycle))
    _declared(lambda: mail.analyze_path(None))
    _declared(lambda: mail.analyze_pff_path(None))

    monkeypatch.setattr(mail, "MAX_INPUT", 32)
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * 33)
    _declared(lambda: mail.analyze_path(large))
    _declared(lambda: mail.analyze_pff_path(large))
    assert mail.main([]) == 2
    assert mail.main(["--not-an-option"]) == 2
