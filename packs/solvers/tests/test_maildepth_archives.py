"""Independent vectors for the bounded mail/chat archive depth engine.

The MSG fixture is a hand-built MS-CFB v3 hierarchy and is read independently
by olefile and extract-msg.  Mbox messages are serialized/read by the stdlib.
Chat JSON follows the vendors' documented export schemas.  Nothing is fetched,
rendered, extracted to attacker-chosen paths, or executed.
"""
from __future__ import annotations

from email import policy
from email.message import EmailMessage
import hashlib
import io
import json
import mailbox
import random
import struct
import zlib
import zipfile

import pytest

import maildepth_archives as target


FLAG = "CSCTF{mail_archive_depth}"
# The attachment is exactly the CFB regular-stream cutoff.  This independently
# exercises both exact logical sizes and the regular FAT while the MAPI text and
# property streams exercise the miniFAT.
ATTACHMENT = b"CSCTF{MSG_ATTACHMENT}\n".ljust(4096, b"A")
DATE = "Fri, 06 Nov 2026 13:00:00 +0000"


def _pff_page(entry: bytes, page_type: int, bid: int) -> bytes:
    """Hand-encode one published 512-byte Unicode NDB leaf page."""

    page = bytearray(512)
    page[:len(entry)] = entry
    struct.pack_into("BBBB", page, 488, 1, 8, len(entry), 0)
    struct.pack_into("BBH", page, 496, page_type, page_type, 0)
    struct.pack_into("<I", page, 500, zlib.crc32(page[:496]) & 0xFFFFFFFF)
    struct.pack_into("<Q", page, 504, bid)
    return bytes(page)


def make_pff(client: bytes = b"SM", version: int = 23) -> bytes:
    """Hand-build a Unicode PFF header plus one NBT and one BBT leaf."""

    raw = bytearray(2560 if version == 23 else (564 if version >= 23 else 512))
    raw[:4] = b"!BDN"
    raw[8:10] = client
    struct.pack_into("<HH", raw, 10, version, 19)
    if version == 23:
        struct.pack_into("<QQ", raw, 0xD8, 0x100, 1024)
        struct.pack_into("<QQ", raw, 0xE8, 0x200, 1536)
        nbt = bytearray(32)
        struct.pack_into("<I", nbt, 0, 0x21)
        struct.pack_into("<Q", nbt, 8, 0x300)
        bbt = struct.pack("<QQHHI", 0x300, 2048, 24, 1, 0)
        raw[1024:1536] = _pff_page(bytes(nbt), 0x81, 0x100)
        raw[1536:2048] = _pff_page(bbt, 0x80, 0x200)
        raw[2048:2072] = b"PFF reference payload".ljust(24, b"!")
    return bytes(raw)


def _fixed_property(pid: int, kind: int, value: int) -> bytes:
    if kind == 0x0003:
        raw = struct.pack("<i", value) + b"\0" * 4
    elif kind == 0x000B:
        raw = struct.pack("<H", int(bool(value))) + b"\0" * 6
    else:  # pragma: no cover - fixture authoring guard
        raise AssertionError(kind)
    return struct.pack("<HHI8s", kind, pid, 0x6, raw)


def _variable_property(pid: int, kind: int, logical_size: int) -> bytes:
    return struct.pack("<HHII", kind, pid, 0x6, logical_size) + b"\0" * 4


def _utf16(value: str) -> bytes:
    return (value + "\0").encode("utf-16-le")


def make_msg() -> bytes:
    """Hand-write a spec-consistent CFB/MSG with one by-value attachment."""
    headers = (
        "From: Alice <alice@example.invalid>\r\n"
        "To: Bob <bob@example.invalid>\r\n"
        "Subject: MSG vector\r\n"
        "Message-ID: <msg@example.invalid>\r\n"
        f"Date: {DATE}"
    )
    logical: dict[str, bytes | None] = {
        "__properties_version1.0": None,
        "__substg1.0_001A001F": _utf16("IPM.Note"),
        "__substg1.0_007D001F": _utf16(headers),
        "__substg1.0_0037001F": _utf16("MSG vector"),
        "__substg1.0_1000001F": _utf16(FLAG),
        "__attach_version1.0_#00000000/__properties_version1.0": None,
        "__attach_version1.0_#00000000/__substg1.0_3707001F": _utf16("evidence.bin"),
        "__attach_version1.0_#00000000/__substg1.0_370E001F":
            _utf16("application/octet-stream"),
        "__attach_version1.0_#00000000/__substg1.0_37010102": ATTACHMENT,
    }
    root_properties = b"\0" * 8 + struct.pack("<4I", 0, 1, 0, 1) + b"\0" * 8
    root_properties += _fixed_property(0x340D, 0x0003, 0x00040000)
    root_properties += _fixed_property(0x0E07, 0x0003, 0x00000010)
    root_properties += _fixed_property(0x0E1B, 0x000B, 1)
    for tag in (0x001A, 0x007D, 0x0037, 0x1000):
        stream = logical[f"__substg1.0_{tag:04X}001F"]
        assert isinstance(stream, bytes)
        root_properties += _variable_property(tag, 0x001F, len(stream))
    logical["__properties_version1.0"] = root_properties

    attachment_properties = b"\0" * 8
    attachment_properties += _fixed_property(0x3705, 0x0003, 1)
    attachment_properties += _fixed_property(0x0E20, 0x0003, len(ATTACHMENT))
    attachment_properties += _fixed_property(0x370B, 0x0003, -1)
    for tag, kind, path in (
        (0x3707, 0x001F, "__attach_version1.0_#00000000/__substg1.0_3707001F"),
        (0x370E, 0x001F, "__attach_version1.0_#00000000/__substg1.0_370E001F"),
        (0x3701, 0x0102, "__attach_version1.0_#00000000/__substg1.0_37010102"),
    ):
        stream = logical[path]
        assert isinstance(stream, bytes)
        attachment_properties += _variable_property(tag, kind, len(stream))
    logical["__attach_version1.0_#00000000/__properties_version1.0"] = attachment_properties

    free, end, fat_marker = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
    specs = [
        {"name": "Root Entry", "kind": 5, "parent": None},
        {"name": "__properties_version1.0", "kind": 2, "parent": 0,
         "path": "__properties_version1.0"},
        {"name": "__substg1.0_001A001F", "kind": 2, "parent": 0,
         "path": "__substg1.0_001A001F"},
        {"name": "__substg1.0_007D001F", "kind": 2, "parent": 0,
         "path": "__substg1.0_007D001F"},
        {"name": "__substg1.0_0037001F", "kind": 2, "parent": 0,
         "path": "__substg1.0_0037001F"},
        {"name": "__substg1.0_1000001F", "kind": 2, "parent": 0,
         "path": "__substg1.0_1000001F"},
        {"name": "__nameid_version1.0", "kind": 1, "parent": 0},
        {"name": "__attach_version1.0_#00000000", "kind": 1, "parent": 0},
        {"name": "__properties_version1.0", "kind": 2, "parent": 7,
         "path": "__attach_version1.0_#00000000/__properties_version1.0"},
        {"name": "__substg1.0_3707001F", "kind": 2, "parent": 7,
         "path": "__attach_version1.0_#00000000/__substg1.0_3707001F"},
        {"name": "__substg1.0_370E001F", "kind": 2, "parent": 7,
         "path": "__attach_version1.0_#00000000/__substg1.0_370E001F"},
        {"name": "__substg1.0_37010102", "kind": 2, "parent": 7,
         "path": "__attach_version1.0_#00000000/__substg1.0_37010102"},
        {"name": "__substg1.0_00020102", "kind": 2, "parent": 6, "empty": True},
        {"name": "__substg1.0_00030102", "kind": 2, "parent": 6, "empty": True},
        {"name": "__substg1.0_00040102", "kind": 2, "parent": 6, "empty": True},
    ]
    for spec in specs:
        spec.update(left=free, right=free, child=free, start=end, size=0, color=1)

    def sort_key(index: int):
        name = specs[index]["name"]
        return len(name), name.upper()

    def wire(indices: list[int]) -> int:
        if not indices:
            return free
        ordered = sorted(indices, key=sort_key)
        middle = len(ordered) // 2
        root = ordered[middle]
        specs[root]["left"] = wire(ordered[:middle])
        specs[root]["right"] = wire(ordered[middle + 1:])
        return root

    for parent in (0, 6, 7):
        specs[parent]["child"] = wire([
            index for index, spec in enumerate(specs) if spec["parent"] == parent
        ])
    # Equalize the red/black height of the four-child attachment tree.
    specs[11]["color"] = 0

    directory_sectors = 4
    mini_fat_sector = 1 + directory_sectors
    next_sector = mini_fat_sector + 1
    regular_bodies: dict[int, bytes] = {}
    mini_stream = bytearray()
    mini_fat = [free] * 128
    next_mini = 0
    for index, spec in enumerate(specs):
        if spec["kind"] != 2 or spec.get("empty"):
            continue
        body = logical[spec["path"]]
        assert isinstance(body, bytes)
        spec["size"] = len(body)
        if len(body) < 4096:
            count = (len(body) + 63) // 64
            spec["start"] = next_mini
            mini_stream.extend(body.ljust(count * 64, b"\0"))
            for mini in range(next_mini, next_mini + count):
                mini_fat[mini] = mini + 1
            mini_fat[next_mini + count - 1] = end
            next_mini += count
        else:
            padded = body.ljust((len(body) + 511) // 512 * 512, b"\0")
            spec["start"] = next_sector
            regular_bodies[index] = padded
            next_sector += len(padded) // 512

    mini_size = len(mini_stream)
    mini_body = bytes(mini_stream).ljust((mini_size + 511) // 512 * 512, b"\0")
    mini_stream_start = next_sector
    specs[0]["start"], specs[0]["size"] = mini_stream_start, mini_size
    next_sector += len(mini_body) // 512
    assert next_sector < 128

    fat = [free] * 128
    fat[0] = fat_marker
    for sector in range(1, 1 + directory_sectors):
        fat[sector] = sector + 1 if sector < directory_sectors else end
    fat[mini_fat_sector] = end
    for index, body in regular_bodies.items():
        start = specs[index]["start"]
        for sector in range(start, start + len(body) // 512):
            fat[sector] = sector + 1
        fat[start + len(body) // 512 - 1] = end
    for sector in range(mini_stream_start, mini_stream_start + len(mini_body) // 512):
        fat[sector] = sector + 1
    fat[mini_stream_start + len(mini_body) // 512 - 1] = end

    def directory_entry(spec: dict) -> bytes:
        raw = bytearray(128)
        encoded = (spec["name"] + "\0").encode("utf-16-le")
        assert len(encoded) <= 64
        raw[:len(encoded)] = encoded
        struct.pack_into("<HBBIII", raw, 64, len(encoded), spec["kind"], spec["color"],
                         spec["left"], spec["right"], spec["child"])
        struct.pack_into("<IQ", raw, 116, spec["start"], spec["size"])
        return bytes(raw)

    directory = b"".join(directory_entry(spec) for spec in specs)
    directory = directory.ljust(directory_sectors * 512, b"\0")
    header = bytearray(512)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 40, 0, 1, 1, 0, 4096,
                     mini_fat_sector, 1, end, 0)
    struct.pack_into("<109I", header, 76, 0, *([free] * 108))
    sectors = {
        sector: directory[(sector - 1) * 512:sector * 512]
        for sector in range(1, 1 + directory_sectors)
    }
    sectors[mini_fat_sector] = struct.pack("<128I", *mini_fat)
    for index, body in regular_bodies.items():
        start = specs[index]["start"]
        for offset in range(0, len(body), 512):
            sectors[start + offset // 512] = body[offset:offset + 512]
    for offset in range(0, len(mini_body), 512):
        sectors[mini_stream_start + offset // 512] = mini_body[offset:offset + 512]
    raw = bytes(header) + struct.pack("<128I", *fat)
    raw += b"".join(sectors[sector] for sector in range(1, next_sector))
    return raw


def make_mbox() -> bytes:
    messages = []
    for ident, parent, text in (
        ("root@example.invalid", None, "root " + FLAG),
        ("reply@example.invalid", "root@example.invalid", "reply"),
    ):
        msg = EmailMessage(policy=policy.default)
        msg["From"] = "Alice <alice@example.invalid>"
        msg["To"] = "Bob <bob@example.invalid>"
        msg["Subject"] = "Grid status"
        msg["Date"] = DATE
        msg["Message-ID"] = f"<{ident}>"
        if parent:
            msg["In-Reply-To"] = f"<{parent}>"
            msg["References"] = f"<{parent}>"
        msg.set_content(text)
        messages.append(msg.as_bytes(policy=policy.default).replace(b"\r\n", b"\n"))
    envelope = b"From alice@example.invalid Fri Nov  6 13:00:00 2026\n"
    return b"".join(envelope + message.rstrip(b"\n") + b"\n\n" for message in messages)


class FakeAttachment:
    long_filename = "grid-state.bin"
    filename = "GRIDST~1.BIN"
    mime_type = "application/octet-stream"

    def __init__(self):
        self.payload = b"PFF-" + FLAG.encode()
        self.size = len(self.payload)

    def read_buffer(self, size):
        return self.payload[:size]


class FakeRecordEntry:
    def __init__(self, *, text=None, integer=None):
        self.data_as_string = text
        self.data_as_integer = integer


class FakeRecipient:
    """Current pypff returns a generic record_set for each recipient."""

    def get_entry_by_type(self, tag):
        return {
            0x3001: FakeRecordEntry(text="Bob Operator"),
            0x39FE: FakeRecordEntry(text="bob@grid.invalid"),
            0x0C15: FakeRecordEntry(integer=1),
        }.get(tag)


class FakeRecipients:
    number_of_recipients = 1

    def get_recipient(self, index):
        assert index == 0
        return FakeRecipient()


class FakeMessage:
    subject = "Black start plan"
    sender_name = "Alice Operator"
    sender_email_address = "alice@grid.invalid"
    transport_headers = ("Message-ID: <pff@grid.invalid>\r\n"
                         "From: alice@grid.invalid\r\nTo: bob@grid.invalid")
    plain_text_body = FLAG.encode()
    html_body = b"<p>inert</p>"
    number_of_attachments = 1
    recipients = FakeRecipients()

    def get_attachment(self, index):
        assert index == 0
        return FakeAttachment()

class FakeFolder:
    def __init__(self, name, messages=(), children=()):
        self.name = name
        self._messages = messages
        self._children = children
        self.number_of_sub_messages = len(messages)
        self.number_of_sub_folders = len(children)

    def get_sub_message(self, index):
        return self._messages[index]

    def get_sub_folder(self, index):
        return self._children[index]


class FakePffHandle:
    def __init__(self, root):
        self.root_folder = root
        self.opened = None
        self.closed = False

    def open(self, path):
        self.opened = path

    def close(self):
        self.closed = True


class FakePffModule:
    def __init__(self, root):
        self.handle = FakePffHandle(root)

    def file(self):
        return self.handle


def slack_export() -> dict[str, bytes]:
    return {
        "users.json": json.dumps([
            {"id": "U1", "name": "alice",
             "profile": {"display_name": "Alice Analyst"}},
            {"id": "U2", "name": "bob", "profile": {"display_name": "Bob"}},
        ]).encode(),
        "channels.json": json.dumps([
            {"id": "C1", "name": "grid-ops", "members": ["U1", "U2"]}
        ]).encode(),
        "grid-ops/2026-11-06.json": json.dumps([
            {"type": "message", "user": "U1", "text": "root " + FLAG,
             "ts": "1793970000.000001", "thread_ts": "1793970000.000001",
             "files": [{"id": "F1", "name": "relay.csv", "mimetype": "text/csv",
                        "size": 123, "url_private": "https://files.slack.invalid/F1"}],
             "reactions": [{"name": "white_check_mark", "count": 1, "users": ["U2"]}]},
            {"type": "message", "user": "U2", "text": "reply",
             "ts": "1793970001.000002", "thread_ts": "1793970000.000001"},
            {"type": "message", "subtype": "message_changed", "ts": "1793970002.000003",
             "message": {"type": "message", "user": "U1", "text": "approved",
                         "ts": "1793970000.000001",
                         "edited": {"user": "U1", "ts": "1793970002.000003"}},
             "previous": {"type": "message", "user": "U1", "text": "pending",
                          "ts": "1793970000.000001"}},
            {"type": "message", "subtype": "message_deleted", "ts": "1793970003.000004",
             "deleted_ts": "1793970001.000002",
             "previous": {"type": "message", "user": "U2", "text": "reply",
                          "ts": "1793970001.000002"}},
        ]).encode(),
    }


def discord_export() -> dict[str, bytes]:
    return {
        "messages/index.json": json.dumps({"123456789012345678": "grid-chat"}).encode(),
        "messages/c123456789012345678/channel.json": json.dumps({
            "id": "123456789012345678", "type": "GUILD_TEXT", "name": "grid-chat",
            "guild": {"id": "987654321098765432", "name": "Grid SOC"},
        }).encode(),
        "messages/c123456789012345678/messages.json": json.dumps([
            {"ID": "111111111111111111", "Timestamp": "2026-11-06T13:00:00+00:00",
             "Contents": FLAG, "Attachments": ["https://cdn.discord.invalid/a/evidence.bin"]},
            {"ID": "111111111111111112", "Timestamp": "2026-11-06T13:01:00+00:00",
             "Contents": "follow-up", "Attachments": []},
        ]).encode(),
    }


def teams_export() -> bytes:
    return json.dumps({"value": [
        {"id": "root-1", "createdDateTime": "2026-11-06T13:00:00Z",
         "lastModifiedDateTime": "2026-11-06T13:00:00Z", "lastEditedDateTime": None,
         "deletedDateTime": None, "chatId": "chat-grid", "messageType": "message",
         "from": {"user": {"id": "aad-1", "displayName": "Alice"}},
         "body": {"contentType": "html", "content": "<p>" + FLAG + "</p>"},
         "attachments": [{"id": "att-1", "name": "relay.csv", "contentType": "reference",
                          "contentUrl": "https://tenant.invalid/relay.csv"}],
         "reactions": [{"reactionType": "like", "user": {"user": {"id": "aad-2"}}}]},
        {"id": "reply-1", "replyToId": "root-1",
         "createdDateTime": "2026-11-06T13:01:00Z",
         "lastModifiedDateTime": "2026-11-06T13:02:00Z",
         "lastEditedDateTime": "2026-11-06T13:02:00Z", "deletedDateTime": None,
         "channelIdentity": {"teamId": "team-1", "channelId": "channel-1"},
         "messageType": "message", "from": {"user": {"id": "aad-2", "displayName": "Bob"}},
         "body": {"contentType": "text", "content": "edited"},
         "messageHistory": [{"modifiedDateTime": "2026-11-06T13:02:00Z",
                             "actions": ["reactionAdded"]}]},
        {"id": "deleted-1", "createdDateTime": "2026-11-06T13:03:00Z",
         "lastModifiedDateTime": "2026-11-06T13:04:00Z",
         "lastEditedDateTime": None, "deletedDateTime": "2026-11-06T13:04:00Z",
         "chatId": "chat-grid", "messageType": "message", "from": None,
         "body": {"contentType": "text", "content": ""}},
    ]}, separators=(",", ":")).encode()


def _messages(result):
    assert isinstance(result, dict)
    return result["messages"]


def test_pff_profile_accepts_documented_pst_and_ost_client_signatures():
    pst = target.inspect_pff(make_pff(b"SM"), "mailbox.pst")
    ost = target.inspect_pff(make_pff(b"SO"), "offline.ost")
    assert pst["format"] == "pst" and pst["client_magic"] == "SM"
    assert ost["format"] == "ost" and ost["client_magic"] == "SO"
    for result in (pst, ost):
        assert result["ndb_version"] == 23 and result["unicode"] is True
        assert result["trees"]["nbt"]["entries"] == [{
            "nid": 0x21, "bid_data": 0x300, "bid_sub": 0,
            "parent_nid": 0, "page": 1024,
        }]
        assert result["trees"]["bbt"]["entries"] == [{
            "bid": 0x300, "file_offset": 2048, "size": 24,
            "references": 1, "page": 1536,
        }]


def test_unicode_pff_header_length_and_modern_4k_backend_contract(tmp_path):
    with pytest.raises(target.MailDepthError, match="header is truncated"):
        target.inspect_pff(make_pff()[:512], "truncated.pst")
    modern = make_pff(b"SO", 36)
    with pytest.raises(target.MailDepthError, match="4-KiB-page"):
        target.inspect_pff(modern, "modern.ost")

    path = tmp_path / "modern.ost"
    path.write_bytes(modern)
    root = FakeFolder("Root", messages=(FakeMessage(),))
    module = FakePffModule(root)
    result = target.analyze_pff_path(path, pypff_module=module)
    assert result["backend"] == "pypff"
    assert result["profile"]["format"] == "ost"
    assert result["profile"]["page_size"] == 4096
    assert result["profile"]["ndb_validation"] == "libpff"
    assert result["profile"]["trees"] is None
    assert result["store"]["counts"]["message_count"] == 1
    assert module.handle.opened == str(path) and module.handle.closed is True


def test_libpff_style_store_traversal_extracts_message_and_attachment_bytes():
    root = FakeFolder("Root", children=(FakeFolder("Inbox", messages=(FakeMessage(),)),))
    result = target.extract_pff_store(root)
    assert result["format"] == "pff-message-store"
    assert result["counts"]["folder_count"] == 2
    assert result["counts"]["message_count"] == 1
    inbox = result["root"]["folders"][0]
    assert inbox["path"] == "Root/Inbox"
    message = inbox["messages"][0]
    assert message["subject"] == "Black start plan"
    assert FLAG in message["bodies"]["plain"]
    assert message["recipients"] == [{
        "name": "Bob Operator", "email": "bob@grid.invalid", "type": "1",
    }]
    attachment = message["attachments"][0]
    expected = FakeAttachment().payload
    assert attachment["filename"] == "grid-state.bin"
    assert attachment["data"] == expected
    assert attachment["sha256"] == hashlib.sha256(expected).hexdigest()


def test_msg_delegation_matches_olefile_and_extract_msg_oracles():
    import extract_msg
    import olefile

    raw = make_msg()
    with olefile.OleFileIO(io.BytesIO(raw)) as ole:
        inventory = {"/".join(path) for path in ole.listdir()}
    assert "__attach_version1.0_#00000000/__substg1.0_37010102" in inventory
    oracle = extract_msg.openMsg(io.BytesIO(raw))
    try:
        expected_subject = oracle.subject.rstrip("\0")
        expected_body = oracle.body.rstrip("\0")
        expected_attachment = oracle.attachments[0].data
        expected_filename = oracle.attachments[0].name.rstrip("\0")
        expected_headers = {
            str(key): str(value).rstrip("\0") for key, value in oracle.header.items()
        }
    finally:
        oracle.close()
    result = target.analyze_msg(raw, "vector.msg")
    message = result["messages"][0]
    assert dict(message["headers"]) == expected_headers
    assert message["subject"] == expected_subject == "MSG vector"
    assert message["bodies"][0] == ["text/plain", expected_body]
    assert expected_body == FLAG
    attachment = message["objects"][0]
    assert attachment["filename"] == expected_filename == "evidence.bin"
    assert attachment["data"] == expected_attachment == ATTACHMENT
    assert attachment["sha256"] == hashlib.sha256(expected_attachment).hexdigest()


def test_mbox_delegation_and_rfc_thread_graph_match_stdlib(tmp_path):
    raw = make_mbox()
    path = tmp_path / "reference.mbox"
    path.write_bytes(raw)
    box = mailbox.mbox(path, create=False)
    try:
        oracle_ids = [str(message["Message-ID"])[1:-1] for message in box]
    finally:
        box.close()
    result = target.analyze_mbox(raw, "reference.mbox")
    messages = result["artifact"]["messages"]
    assert [message["message_id"] for message in messages] == oracle_ids
    assert messages[0]["bodies"] == [["text/plain", "root " + FLAG + "\n"]]
    assert messages[1]["in_reply_to"] == ["root@example.invalid"]
    assert len(result["threads"]) == 1
    thread = result["threads"][0]
    assert thread["root_id"] == "root@example.invalid"
    assert thread["message_ids"] == oracle_ids
    assert thread["edges"] == [["root@example.invalid", "reply@example.invalid"]]


def test_slack_official_export_channels_threads_edits_and_metadata_only():
    result = target.parse_slack_export(slack_export())
    assert result["platform"] == "slack"
    assert result["channels"] == [{
        "id": "C1", "name": "grid-ops", "kind": "channel", "members": ["U1", "U2"]
    }]
    messages = _messages(result)
    root = next(message for message in messages if message["id"] == "1793970000.000001")
    reply = next(message for message in messages if message["id"] == "1793970001.000002")
    assert root["sender_name"] == "Alice Analyst" and FLAG in root["flags"]
    assert root["attachments"][0]["name"] == "relay.csv"
    assert "data" not in root["attachments"][0]
    assert reply["parent_id"] == root["id"]
    assert any(message["edited"] is not None and message["edit_history"] for message in messages)
    assert any(message["deleted"] is True for message in messages)


def test_slack_zip_export_is_parsed_in_memory_without_extracting(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    expected = target.parse_slack_export(slack_export())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in slack_export().items():
            archive.writestr(name, body)
    assert target.parse_slack_export(buffer.getvalue(), name="slack.zip") == expected
    assert list(tmp_path.iterdir()) == []


def test_discord_official_package_preserves_snowflakes_and_links_only():
    result = target.parse_discord_export(discord_export())
    assert result["platform"] == "discord"
    assert result["channels"][0]["id"] == "123456789012345678"
    message = _messages(result)[0]
    assert message["id"] == "111111111111111111"
    assert message["conversation_name"] == "grid-chat"
    assert FLAG in message["flags"]
    assert message["attachments"][0]["url"] == "https://cdn.discord.invalid/a/evidence.bin"
    assert "data" not in message["attachments"][0]


def test_teams_graph_export_replies_edits_deletes_and_attachments():
    result = target.parse_teams_export(teams_export())
    assert result["platform"] == "teams"
    messages = _messages(result)
    root = next(message for message in messages if message["id"] == "root-1")
    reply = next(message for message in messages if message["id"] == "reply-1")
    deleted = next(message for message in messages if message["id"] == "deleted-1")
    assert root["body_format"] == "html" and FLAG in root["flags"]
    assert root["attachments"][0]["name"] == "relay.csv"
    assert reply["parent_id"] == "root-1" and reply["edited"] == "2026-11-06T13:02:00Z"
    assert reply["edit_history"][0]["actions"] == ["reactionAdded"]
    assert deleted["deleted"] is True


@pytest.mark.parametrize("platform,fixture", [
    ("slack", slack_export), ("discord", discord_export), ("teams", teams_export),
])
def test_auto_chat_dispatch_matches_explicit_parser(platform, fixture):
    value = fixture()
    expected = getattr(target, f"parse_{platform}_export")(value, name="same.json")
    assert target.parse_chat_export(value, platform=platform, name="same.json") == expected
    assert target.parse_chat_export(value, platform="auto", name="same.json") == expected


def _malformed_corpus():
    rng = random.Random(0x4D41494C)
    corpus = [b"", b"\0", b"\xff" * 512, b"%PDF", b"%PDF-1.7\n",
              b"!BDN", bytes.fromhex("d0cf11e0a1b11ae1"), b"PK\x03\x04",
              b"{", b"[]", b"{}", b'{"x":1,"x":2}', b"[NaN]"]
    corpus.extend(rng.randbytes(size) for size in (1, 2, 7, 31, 127, 511, 1024))
    for valid in (make_pff(), make_msg(), make_mbox(), teams_export()):
        corpus.extend(valid[:end] for end in (1, 3, 7, 15, min(511, len(valid) - 1), len(valid) - 1))
        for offset in (0, min(8, len(valid) - 1), len(valid) // 2, len(valid) - 1):
            changed = bytearray(valid)
            changed[offset] ^= 0x80
            corpus.append(bytes(changed))
    return corpus


def _fail_closed(call):
    try:
        value = call()
    except target.MailDepthError as exc:
        assert type(exc) is target.MailDepthError
    else:
        assert value is None or isinstance(value, dict)


def test_public_byte_parsers_fail_closed_on_truncation_random_and_bitflips():
    for data in _malformed_corpus():
        _fail_closed(lambda data=data: target.inspect_pff(data, "fuzz.pst"))
        _fail_closed(lambda data=data: target.extract_pff_store(data))
        _fail_closed(lambda data=data: target.analyze_msg(data, "fuzz.msg"))
        _fail_closed(lambda data=data: target.analyze_mbox(data, "fuzz.mbox"))
        _fail_closed(lambda data=data: target.parse_slack_export(data))
        _fail_closed(lambda data=data: target.parse_discord_export(data))
        _fail_closed(lambda data=data: target.parse_teams_export(data))
        _fail_closed(lambda data=data: target.parse_chat_export(data, platform="auto"))
        _fail_closed(lambda data=data: target.analyze_bytes(data, name="fuzz.bin"))


@pytest.mark.parametrize("bad", [None, True, 7, 1.5, "text", [], object()])
def test_public_parsers_wrong_types_leak_no_stdlib_exception(bad):
    for function in (
        lambda: target.inspect_pff(bad, "bad.pst"),
        lambda: target.extract_pff_store(bad),
        lambda: target.analyze_msg(bad, "bad.msg"),
        lambda: target.analyze_mbox(bad, "bad.mbox"),
        lambda: target.parse_slack_export(bad),
        lambda: target.parse_discord_export(bad),
        lambda: target.parse_teams_export(bad),
        lambda: target.parse_chat_export(bad),
        lambda: target.analyze_bytes(bad, name="bad.bin"),
    ):
        _fail_closed(function)


def test_cli_is_guarded_and_offline(tmp_path, capsys):
    fixture = tmp_path / "teams.json"
    fixture.write_bytes(teams_export())
    assert target.main([str(fixture), "--platform", "teams"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["input"] == str(fixture)
    assert output["result"]["platform"] == "teams"
    assert target.main([]) == 2
    assert target.main(["--not-an-option"]) == 2

