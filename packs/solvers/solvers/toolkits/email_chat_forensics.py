"""Fail-closed offline e-mail threading and SQLite chat extraction.

All APIs consume bytes already supplied by the caller.  MIME data is accepted only when the
repository's mature mail reader reports a complete, defect-free message; attachments and inline
objects are returned only when their transfer encoding is exact.  Chat databases use recognized
schemas and an optional checksum-valid supplied WAL.  No URL, attachment, or external media path
is opened by this module.
"""

from __future__ import annotations

import datetime as dt
import base64
import binascii
import hashlib
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:
    import browser_forensics as _browser
    import sqlite_artifacts as _sqlite
except ImportError:
    from . import browser_forensics as _browser
    from . import sqlite_artifacts as _sqlite


MAX_MAIL = 128 << 20
MAX_MESSAGES = 100_000
MAX_PARTS = 10_000
MAX_BODY = 16 << 20
MAX_ATTACHMENT = 64 << 20
MAX_TOTAL_ATTACHMENTS = 256 << 20
MAX_HEADER = 1 << 20
MAX_CHAT_ROWS = 250_000
MAX_CHAT_BYTES = 512 << 20
UTC = dt.timezone.utc
_MSGID = re.compile(r"<([^<>\s\x00-\x1f\x7f]+@[^<>\s\x00-\x1f\x7f]+)>")


def _load_mailtool():
    name = "_r5e_existing_email_reader"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().with_name("email.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("mail reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_mailtool = _load_mailtool()


@dataclass(frozen=True, slots=True)
class EmailObject:
    filename: str | None
    media_type: str
    disposition: str | None
    content_id: str | None
    inline: bool
    data: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class EmailMessage:
    artifact: str
    message_id: str | None
    in_reply_to: tuple[str, ...]
    references: tuple[str, ...]
    subject: str | None
    sender: str | None
    recipients: tuple[str, ...]
    date: str | None
    bodies: tuple[tuple[str, str], ...]
    objects: tuple[EmailObject, ...]
    headers: tuple[tuple[str, str], ...]
    sha256: str | None


@dataclass(frozen=True, slots=True)
class EmailArtifact:
    kind: str
    messages: tuple[EmailMessage, ...]
    sha256: str


@dataclass(frozen=True, slots=True)
class EmailThread:
    root_id: str
    message_ids: tuple[str, ...]
    edges: tuple[tuple[str, str], ...]
    messages: tuple[EmailMessage, ...]


@dataclass(frozen=True, slots=True)
class ChatMessage:
    identifier: str
    thread_id: str
    sender: str | None
    text: str | None
    timestamp: str | None
    from_me: bool | None
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ChatAttachment:
    identifier: str
    message_id: str
    filename: str | None
    media_type: str | None
    data: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ChatArchive:
    schema: str
    threads: tuple[tuple[str, str | None], ...]
    messages: tuple[ChatMessage, ...]
    attachments: tuple[ChatAttachment, ...]
    wal_frames: int
    sha256: str


def _blob(value: object, cap: int) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    if len(value) > cap:
        return None
    raw = bytes(value)
    return raw if raw and len(raw) <= cap else None


def _text(value: object, cap: int = MAX_HEADER, *, empty: bool = False) -> str | None:
    if not isinstance(value, str) or len(value) > cap or "\x00" in value:
        return None
    if not value and not empty:
        return None
    return value


def _ids(value: object, *, exactly_one: bool = False) -> tuple[str, ...] | None:
    if value is None or value == "":
        return ()
    if not isinstance(value, str) or len(value) > MAX_HEADER:
        return None
    matches = tuple(match.group(1) for match in _MSGID.finditer(value))
    residue = _MSGID.sub("", value)
    if residue.strip() or not matches or exactly_one and len(matches) != 1:
        return None
    return matches


def _address(header: object) -> str | None:
    if header is None:
        return None
    text = _text(header)
    if text is None or "\r" in text or "\n" in text:
        return None
    return text


def _mail_date(value: object) -> str | None:
    if value is None:
        return None
    text = _text(value)
    if text is None:
        return None
    try:
        import email.utils
        parsed = email.utils.parsedate_to_datetime(text)
        if parsed is None or parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _validate_content_md5(raw: bytes) -> bool:
    try:
        from email import policy
        from email.parser import BytesParser

        body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
        body = body.lstrip(b"\r\n")
        message = BytesParser(policy=policy.default).parsebytes(body)
    except Exception:
        return False
    parts = 0
    total = 0
    try:
        for part in message.walk():
            parts += 1
            if parts > MAX_PARTS or part.defects:
                return False
            values = part.get_all("Content-MD5", [])
            if len(values) > 1:
                return False
            if not values:
                continue
            token = str(values[0]).strip()
            if not re.fullmatch(r"[A-Za-z0-9+/]{22}==", token):
                return False
            try:
                expected = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                return False
            if len(expected) != 16 or base64.b64encode(expected).decode("ascii") != token:
                return False
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                return False
            total += len(payload)
            if len(payload) > MAX_ATTACHMENT or total > MAX_TOTAL_ATTACHMENTS:
                return False
            if hashlib.md5(payload).digest() != expected:
                return False
    except Exception:
        return False
    return True


def _mbox_messages(raw: bytes, expected: int) -> tuple[bytes, ...] | None:
    try:
        starts = [match.start() for match in re.finditer(rb"(?m)^From [^\r\n]*\r?\n", raw)]
    except Exception:
        return None
    if len(starts) != expected or not starts or starts[0] != 0:
        return None
    out: list[bytes] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(raw)
        chunk = raw[start:end]
        newline = chunk.find(b"\n")
        if newline < 0:
            return None
        message = re.sub(rb"(?m)^>(>*From )", rb"\1", chunk[newline + 1:])
        out.append(message.rstrip(b"\r\n") + b"\n")
    return tuple(out)


def _one_mail(mail: object, artifact: str, *, content_md5_checked: bool) -> EmailMessage | None:
    doubt = getattr(mail, "doubt", None)
    mbox_doubt = getattr(mail, "mbox_doubt", None)
    if not isinstance(doubt, list) or doubt or mbox_doubt:
        return None
    headers = getattr(mail, "headers", None)
    if not isinstance(headers, list) or len(headers) > MAX_PARTS:
        return None
    checked_headers: list[tuple[str, str]] = []
    total_header = 0
    for pair in headers:
        if not isinstance(pair, tuple) or len(pair) != 2:
            return None
        name, value = pair
        if not isinstance(name, str) or not re.fullmatch(r"[!-9;-~]+", name):
            return None
        if _text(value, MAX_HEADER, empty=True) is None:
            return None
        total_header += len(name) + len(value)
        if total_header > MAX_HEADER:
            return None
        checked_headers.append((name, value))

    if any(name.lower() == "content-md5" for name, _value in checked_headers) and not content_md5_checked:
        return None

    def all_headers(name: str) -> list[str]:
        return [value for key, value in checked_headers if key.lower() == name]

    message_headers = all_headers("message-id")
    if len(message_headers) > 1:
        return None
    message_id_values = _ids(message_headers[0], exactly_one=True) if message_headers else ()
    if message_id_values is None:
        return None
    reply_headers = all_headers("in-reply-to")
    reference_headers = all_headers("references")
    if len(reply_headers) > 1 or len(reference_headers) > 1:
        return None
    replies = _ids(reply_headers[0]) if reply_headers else ()
    references = _ids(reference_headers[0]) if reference_headers else ()
    if replies is None or references is None:
        return None
    subjects = all_headers("subject")
    dates = all_headers("date")
    senders = all_headers("from")
    if len(subjects) > 1 or len(dates) > 1 or len(senders) > 1:
        return None
    subject = _text(subjects[0], MAX_HEADER, empty=True) if subjects else None
    sender = _address(senders[0]) if senders else None
    when = _mail_date(dates[0]) if dates else None
    if dates and when is None or senders and sender is None:
        return None
    recipients: list[str] = []
    for name in ("to", "cc", "bcc"):
        for value in all_headers(name):
            got = _address(value)
            if got is None:
                return None
            recipients.append(got)

    bodies = getattr(mail, "bodies", None)
    attachments = getattr(mail, "attachments", None)
    if not isinstance(bodies, list) or not isinstance(attachments, list):
        return None
    if len(bodies) + len(attachments) > MAX_PARTS:
        return None
    body_out: list[tuple[str, str]] = []
    for body in bodies:
        if not isinstance(body, Mapping):
            return None
        media, content = body.get("type"), body.get("text")
        if not isinstance(media, str) or not isinstance(content, str):
            return None
        try:
            encoded_length = len(content.encode("utf-8"))
        except UnicodeEncodeError:
            return None
        if encoded_length > MAX_BODY:
            return None
        body_out.append((media, content))
    object_out: list[EmailObject] = []
    content_ids: dict[str, str] = {}
    total = 0
    for item in attachments:
        if not isinstance(item, Mapping) or item.get("exact") is not True:
            return None
        data = item.get("data")
        if not isinstance(data, bytes) or not data or len(data) > MAX_ATTACHMENT:
            return None
        total += len(data)
        if total > MAX_TOTAL_ATTACHMENTS:
            return None
        digest = hashlib.sha256(data).hexdigest()
        if item.get("size") != len(data) or item.get("sha256") != digest:
            return None
        filename = item.get("filename")
        media = item.get("declared_type")
        disposition = item.get("disposition")
        content_id = item.get("content_id")
        if filename is not None and _text(filename, 4096) is None:
            return None
        if not isinstance(media, str) or _text(media, 256) is None:
            return None
        if disposition is not None and disposition not in {"inline", "attachment"}:
            return None
        if content_id is not None and _text(content_id, 4096) is None:
            return None
        if content_id is not None:
            previous = content_ids.get(content_id)
            if previous is not None and previous != digest:
                return None
            content_ids[content_id] = digest
        inline = disposition == "inline" or content_id is not None
        object_out.append(EmailObject(filename, media, disposition, content_id, inline, data, digest))
    raw = getattr(mail, "raw", None)
    digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) and raw else None
    return EmailMessage(
        artifact=artifact,
        message_id=message_id_values[0] if message_id_values else None,
        in_reply_to=tuple(replies),
        references=tuple(references),
        subject=subject,
        sender=sender,
        recipients=tuple(recipients),
        date=when,
        bodies=tuple(body_out),
        objects=tuple(object_out),
        headers=tuple(checked_headers),
        sha256=digest,
    )


def decode_email_artifact(data: object, *, name: str = "message.eml") -> EmailArtifact | None:
    """Decode a complete EML, MSG, or mbox including exact attachments and inline objects."""
    raw = _blob(data, MAX_MAIL)
    if raw is None or not isinstance(name, str) or not name or len(name) > 4096:
        return None
    try:
        mails = _mailtool.load(raw, name)
    except Exception:
        return None
    if not isinstance(mails, list) or not mails or len(mails) > MAX_MESSAGES:
        return None
    kinds = {getattr(mail, "kind", None) for mail in mails}
    if len(kinds) != 1 or next(iter(kinds)) not in {"eml", "msg", "mbox"}:
        return None
    kind = next(iter(kinds))
    if kind == "eml":
        md5_checks = (_validate_content_md5(raw),)
    elif kind == "mbox":
        chunks = _mbox_messages(raw, len(mails))
        if chunks is None:
            return None
        md5_checks = tuple(_validate_content_md5(chunk) for chunk in chunks)
    else:
        # MAPI attachments do not retain MIME Content-MD5 fields.  Top-level occurrences are
        # conservatively rejected by _one_mail because they cannot be tied to exact part bytes.
        md5_checks = tuple(False for _ in mails)
    if len(md5_checks) != len(mails) or not all(md5_checks) and kind != "msg":
        return None
    messages: list[EmailMessage] = []
    for index, mail in enumerate(mails):
        parsed = _one_mail(mail, name if len(mails) == 1 else f"{name}#{index + 1}",
                           content_md5_checked=md5_checks[index])
        if parsed is None:
            return None
        messages.append(parsed)
    return EmailArtifact(kind, tuple(messages), hashlib.sha256(raw).hexdigest())


def _bounded_mapping_items(value: object, cap: int) -> list[tuple[object, object]] | None:
    if not isinstance(value, Mapping):
        return None
    try:
        count = len(value)
        if count < 0 or count > cap:
            return None
        iterator = iter(value.items())
        out: list[tuple[object, object]] = []
        for _ in range(count):
            item = next(iterator)
            if not isinstance(item, tuple) or len(item) != 2:
                return None
            out.append(item)
        try:
            next(iterator)
        except StopIteration:
            return out
        return None
    except Exception:
        return None


def _bounded_sequence_items(value: object, cap: int) -> list[object] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray, memoryview)):
        return None
    try:
        count = len(value)
        if count < 0 or count > cap:
            return None
        out = [value[index] for index in range(count)]
        try:
            value[count]
        except IndexError:
            return out
        except Exception:
            return None
        return None
    except Exception:
        return None


def build_email_threads(artifacts: Mapping[str, object] | Sequence[object]) -> tuple[EmailThread, ...] | None:
    """Build RFC Message-ID threads; no subject/date proximity fallback is used."""
    if isinstance(artifacts, Mapping):
        mapped = _bounded_mapping_items(artifacts, MAX_MESSAGES)
        if mapped is None:
            return None
        entries = mapped
    elif isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes, bytearray, memoryview)):
        values = _bounded_sequence_items(artifacts, MAX_MESSAGES)
        if values is None:
            return None
        entries = [(f"message-{index + 1}.eml", value) for index, value in enumerate(values)]
    else:
        return None
    messages: list[EmailMessage] = []
    for name, value in entries:
        if not isinstance(name, str):
            return None
        decoded = decode_email_artifact(value, name=name)
        if decoded is None:
            return None
        messages.extend(decoded.messages)
        if len(messages) > MAX_MESSAGES:
            return None
    if not messages or any(message.message_id is None for message in messages):
        return None
    by_id: dict[str, EmailMessage] = {}
    for message in messages:
        assert message.message_id is not None
        if message.message_id in by_id:
            return None
        by_id[message.message_id] = message
    parent: dict[str, str] = {}
    for message in messages:
        assert message.message_id is not None
        local = [candidate for candidate in message.in_reply_to if candidate in by_id]
        if not local:
            local = [candidate for candidate in message.references if candidate in by_id][-1:]
        if len(set(local)) > 1:
            return None
        if local:
            if local[-1] == message.message_id:
                return None
            parent[message.message_id] = local[-1]
    for identifier in by_id:
        seen: set[str] = set()
        node = identifier
        while node in parent:
            if node in seen:
                return None
            seen.add(node)
            node = parent[node]
    groups: dict[str, list[EmailMessage]] = {}
    for message in messages:
        assert message.message_id is not None
        root = message.message_id
        while root in parent:
            root = parent[root]
        groups.setdefault(root, []).append(message)
    result: list[EmailThread] = []
    order = {message.message_id: index for index, message in enumerate(messages)}
    for root, group in groups.items():
        group.sort(key=lambda message: order[message.message_id])
        identifiers = tuple(message.message_id for message in group if message.message_id is not None)
        edges = tuple((parent[identifier], identifier) for identifier in identifiers if identifier in parent)
        result.append(EmailThread(root, identifiers, edges, tuple(group)))
    result.sort(key=lambda thread: order[thread.root_id])
    return tuple(result)


def _columns(db: _sqlite.Database) -> dict[str, set[str]]:
    return {table: {column[0] for column in values} for table, values in db.columns.items()}


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _identifier(value: object) -> str | None:
    number = _int(value)
    if number is not None:
        return str(number)
    return _text(value, 4096) if isinstance(value, str) else None


def _flag(value: object, *, optional: bool = True) -> bool | None:
    if value is None and optional:
        return None
    number = _int(value)
    return bool(number) if number in (0, 1) else None


def _digest_bytes(value: object, algorithm: str | None) -> bytes | None:
    sizes = {"md5": 16, "sha256": 32}
    if isinstance(value, bytes):
        if algorithm is not None:
            return value if len(value) == sizes[algorithm] else None
        return value if len(value) in sizes.values() else None
    if not isinstance(value, str):
        return None
    if algorithm is not None:
        size = sizes[algorithm]
        if len(value) != size * 2 or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
            return None
    elif len(value) not in (32, 64) or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _declared_digests(row: Mapping[str, object], body: bytes | None = None) -> bool:
    for column, algorithm in (("md5", "md5"), ("sha256", "sha256"), ("digest", None)):
        value = row.get(column)
        if value is None:
            continue
        expected = _digest_bytes(value, algorithm)
        if expected is None:
            return False
        if body is not None:
            actual = hashlib.md5(body).digest() if len(expected) == 16 else hashlib.sha256(body).digest()
            if actual != expected:
                return False
    return True


def _chat_database_bounded(db: _sqlite.Database) -> bool:
    rows_seen = 0
    bytes_seen = 0
    try:
        for table, rows in db.tables.items():
            if not isinstance(table, str) or table.startswith("sqlite_"):
                continue
            rows_seen += len(rows)
            if rows_seen > MAX_CHAT_ROWS:
                return False
            for row in rows:
                if not isinstance(row, Mapping):
                    return False
                for value in row.values():
                    if isinstance(value, (str, bytes)):
                        size = len(value)
                        if size > MAX_CHAT_BYTES:
                            return False
                        bytes_seen += size
                        if bytes_seen > MAX_CHAT_BYTES:
                            return False
                    elif value is not None and not isinstance(value, (int, float)):
                        return False
    except Exception:
        return False
    return True


def _chat_schema(db: _sqlite.Database) -> str | None:
    columns = _columns(db)

    def has(table: str, *names: str) -> bool:
        return table in columns and all(name in columns[table] for name in names)

    matches: list[str] = []
    if has("message", "text", "is_from_me", "date", "handle_id") and has("handle", "id"):
        matches.append("ios_sms")
    if has("messages", "key_remote_jid", "data"):
        matches.append("whatsapp_msgstore_old")
    if has("message", "text_data") and has("jid"):
        matches.append("whatsapp_msgstore_new")
    if (has("threads", "id", "title")
            and has("messages", "id", "thread_id", "sender", "body", "timestamp_ms")):
        matches.append("generic_chat")

    # A browser database with chat-shaped decoy tables is not treated as a chat archive.
    foreign = (
        (has("urls", "url", "visit_count") and "visits" in columns)
        or has("downloads", "target_path") or has("downloads", "url")
        or has("cookies", "host_key", "name") or has("moz_places", "url")
        or has("moz_cookies", "host", "name") or has("webappsstore2", "key", "value")
        or (has("history_items", "url") and has("history_visits", "visit_time"))
        or has("ItemTable", "key", "value") or has("object_data", "object_store_id", "key", "data")
        or (has("cfurl_cache_response", "entry_ID", "request_key")
            and has("cfurl_cache_receiver_data", "entry_ID", "receiver_data"))
    )
    return matches[0] if len(matches) == 1 and not foreign else None


def _timestamp_ms(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    try:
        return (dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(milliseconds=number)).isoformat()
    except OverflowError:
        return None


def _timestamp_mac(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    try:
        parsed = _sqlite.from_mac_absolute(number)
        return parsed.isoformat() if parsed is not None else None
    except Exception:
        return None


def _row_meta(row: Mapping[str, object], skip: set[str]) -> tuple[tuple[str, str], ...]:
    out = []
    for key, value in row.items():
        if key in skip or key.startswith("_") or value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            text = str(value)
            if len(key) <= 128 and len(text) <= 4096:
                out.append((key, text))
    return tuple(sorted(out)[:128])


def _generic_chat(db: _sqlite.Database) -> tuple[tuple[tuple[str, str | None], ...],
                                                  tuple[ChatMessage, ...],
                                                  tuple[ChatAttachment, ...]] | None:
    columns = _columns(db)
    if not ({"id", "title"} <= columns.get("threads", set())
            and {"id", "thread_id", "sender", "body", "timestamp_ms"} <= columns.get("messages", set())):
        return None
    thread_rows = db.rows("threads", recovered=False)
    message_rows = db.rows("messages", recovered=False)
    if "attachments" in columns and not {"id", "message_id", "data"} <= columns["attachments"]:
        return None
    attachment_rows = db.rows("attachments", recovered=False) if "attachments" in columns else []
    if len(thread_rows) + len(message_rows) + len(attachment_rows) > MAX_CHAT_ROWS:
        return None
    threads: list[tuple[str, str | None]] = []
    thread_ids: set[str] = set()
    for row in thread_rows:
        ident = _identifier(row.get("id"))
        title = row.get("title")
        if ident is None or ident in thread_ids or title is not None and _text(title, 4096, empty=True) is None:
            return None
        thread_ids.add(ident)
        threads.append((ident, title))
    messages: list[ChatMessage] = []
    message_ids: set[str] = set()
    for row in message_rows:
        raw_id, raw_thread = row.get("id"), row.get("thread_id")
        ident, thread = _identifier(raw_id), _identifier(raw_thread)
        if ident is None or thread is None:
            return None
        sender, body = row.get("sender"), row.get("body")
        when = _timestamp_ms(row.get("timestamp_ms"))
        if ident in message_ids or thread not in thread_ids or when is None:
            return None
        if sender is not None and _text(sender, 4096, empty=True) is None:
            return None
        if body is not None and _text(body, MAX_BODY, empty=True) is None:
            return None
        from_me = row.get("from_me")
        checked_from_me = _flag(from_me)
        if from_me is not None and checked_from_me is None:
            return None
        message_ids.add(ident)
        messages.append(ChatMessage(ident, thread, sender, body, when,
                                    checked_from_me,
                                    _row_meta(row, {"id", "thread_id", "sender", "body", "timestamp_ms", "from_me"})))
    attachments: list[ChatAttachment] = []
    total = 0
    if "attachments" in columns:
        attachment_ids: set[str] = set()
        for row in attachment_rows:
            raw_id, raw_message = row.get("id"), row.get("message_id")
            data = row.get("data")
            ident, message_id = _identifier(raw_id), _identifier(raw_message)
            if ident is None or message_id is None:
                return None
            if ident in attachment_ids or message_id not in message_ids or not isinstance(data, bytes) or not data or len(data) > MAX_ATTACHMENT:
                return None
            total += len(data)
            if total > MAX_TOTAL_ATTACHMENTS:
                return None
            filename, media = row.get("filename"), row.get("mime")
            if filename is not None and _text(filename, 4096) is None or media is not None and _text(media, 256) is None:
                return None
            digest = hashlib.sha256(data).hexdigest()
            if not _declared_digests(row, data):
                return None
            attachment_ids.add(ident)
            attachments.append(ChatAttachment(ident, message_id, filename, media, data, digest))
    return tuple(threads), tuple(messages), tuple(attachments)


def _ios_chat(db: _sqlite.Database,
              sidecars: dict[str, bytes] | None) -> tuple[tuple[tuple[str, str | None], ...],
                                                          tuple[ChatMessage, ...],
                                                          tuple[ChatAttachment, ...]] | None:
    columns = _columns(db)
    if not ({"text", "is_from_me", "date", "handle_id"} <= columns.get("message", set())
            and "id" in columns.get("handle", set())):
        return None
    rows = db.rows("message", recovered=False)
    message_rowids: set[int] = set()
    for row in rows:
        rowid = _int(row.get("ROWID", row.get("_rowid")))
        if rowid is None or rowid in message_rowids:
            return None
        message_rowids.add(rowid)

    handles: dict[int, str] = {}
    for row in db.rows("handle", recovered=False):
        rowid = _int(row.get("ROWID", row.get("_rowid")))
        address = _text(row.get("id"), 4096)
        if rowid is None or rowid in handles or address is None:
            return None
        handles[rowid] = address

    if "chat_message_join" in columns:
        if "chat" not in columns or not {"chat_id", "message_id"} <= columns["chat_message_join"]:
            return None
    chat_names: dict[int, str | None] = {}
    if "chat" in columns:
        if not ({"display_name", "chat_identifier"} & columns["chat"]):
            return None
        for row in db.rows("chat", recovered=False):
            rowid = _int(row.get("ROWID", row.get("_rowid")))
            display = row.get("display_name")
            identifier = row.get("chat_identifier")
            if (rowid is None or rowid in chat_names
                    or display is not None and _text(display, 4096, empty=True) is None
                    or identifier is not None and _text(identifier, 4096, empty=True) is None):
                return None
            chat_names[rowid] = display or identifier

    joins: dict[int, list[int]] = {}
    seen_chat_joins: set[tuple[int, int]] = set()
    if "chat_message_join" in columns:
        for row in db.rows("chat_message_join", recovered=False):
            message_id, chat_id = _int(row.get("message_id")), _int(row.get("chat_id"))
            if message_id is None or chat_id is None:
                return None
            pair = (message_id, chat_id)
            if (pair in seen_chat_joins or message_id not in message_rowids
                    or chat_id not in chat_names):
                return None
            seen_chat_joins.add(pair)
            joins.setdefault(message_id, []).append(chat_id)

    threads: dict[str, str | None] = {}
    messages: list[ChatMessage] = []
    message_ids: set[str] = set()
    for row in rows:
        raw_id = _int(row.get("ROWID", row.get("_rowid")))
        assert raw_id is not None
        ident = str(raw_id)
        chat_ids = joins.get(raw_id, [])
        if len(chat_ids) > 1:
            return None
        handle_id = _int(row.get("handle_id"))
        if handle_id is None or handle_id not in handles:
            return None
        raw_thread = chat_ids[0] if chat_ids else handle_id
        thread = str(raw_thread)
        text = row.get("text")
        if text is not None and _text(text, MAX_BODY, empty=True) is None:
            return None
        when = _timestamp_mac(row.get("date"))
        from_me = _flag(row.get("is_from_me"), optional=False)
        if when is None or from_me is None:
            return None
        sender = handles[handle_id]
        title = chat_names.get(raw_thread)
        if ident in message_ids:
            return None
        threads.setdefault(thread, title)
        message_ids.add(ident)
        messages.append(ChatMessage(ident, thread, sender, text, when, from_me))

    attachments: list[ChatAttachment] = []
    total = 0
    if ("attachment" in columns) != ("message_attachment_join" in columns):
        return None
    used_sidecars: set[str] = set()
    if "attachment" in columns:
        if ("filename" not in columns["attachment"]
                or not {"message_id", "attachment_id"} <= columns["message_attachment_join"]):
            return None
        attachment_rows: dict[int, Mapping[str, object]] = {}
        paths: set[str] = set()
        for row in db.rows("attachment", recovered=False):
            aid = _int(row.get("ROWID", row.get("_rowid")))
            path, media = row.get("filename"), row.get("mime_type")
            expected_size = row.get("total_bytes")
            if (aid is None or aid in attachment_rows
                    or path is not None and _text(path, 4096) is None
                    or media is not None and _text(media, 256) is None
                    or expected_size is not None and (_int(expected_size) is None or expected_size < 0)
                    or not _declared_digests(row)):
                return None
            if path is not None:
                if path in paths:
                    return None
                paths.add(path)
            attachment_rows[aid] = row

        relation: dict[int, int] = {}
        seen_attachment_joins: set[tuple[int, int]] = set()
        for row in db.rows("message_attachment_join", recovered=False):
            message_id, aid = _int(row.get("message_id")), _int(row.get("attachment_id"))
            if message_id is None or aid is None:
                return None
            pair = (message_id, aid)
            if (pair in seen_attachment_joins or message_id not in message_rowids
                    or aid not in attachment_rows or aid in relation):
                return None
            seen_attachment_joins.add(pair)
            relation[aid] = message_id

        supplied = sidecars or {}
        for aid, row in attachment_rows.items():
            path = row.get("filename")
            message_id = relation.get(aid)
            if message_id is None or not isinstance(path, str) or path not in supplied:
                continue
            body = supplied[path]
            if not body or len(body) > MAX_ATTACHMENT or not _declared_digests(row, body):
                return None
            total += len(body)
            if total > MAX_TOTAL_ATTACHMENTS:
                return None
            expected = row.get("total_bytes")
            if expected is not None and expected != len(body):
                return None
            used_sidecars.add(path)
            media = row.get("mime_type")
            attachments.append(ChatAttachment(str(aid), str(message_id), path, media,
                                              body, hashlib.sha256(body).hexdigest()))
    if set(sidecars or {}) != used_sidecars:
        return None
    return tuple(sorted(threads.items())), tuple(messages), tuple(attachments)


def _whatsapp_chat(db: _sqlite.Database) -> tuple[tuple[tuple[str, str | None], ...],
                                                   tuple[ChatMessage, ...],
                                                   tuple[ChatAttachment, ...]] | None:
    try:
        records = _sqlite.records(db, art="chat")
    except Exception:
        return None
    rows = [record for record in records if record.get("kind") == "message" and record.get("src") == "live"]
    if not rows or len(rows) > MAX_CHAT_ROWS:
        return None
    messages: list[ChatMessage] = []
    threads: dict[str, str | None] = {}
    identifiers: set[str] = set()
    for index, record in enumerate(rows):
        fields, times = record.get("f"), record.get("t")
        if not isinstance(fields, Mapping) or not isinstance(times, Mapping):
            return None
        sender = fields.get("sender")
        text = fields.get("text")
        if _text(sender, 4096) is None or text is not None and _text(text, MAX_BODY, empty=True) is None:
            return None
        time_pair = times.get("time")
        if not isinstance(time_pair, tuple) or len(time_pair) != 2 or time_pair[1] is None:
            return None
        when = time_pair[1].isoformat()
        thread = sender
        threads.setdefault(thread, None)
        raw_from_me = fields.get("from_me")
        from_me = _flag(raw_from_me)
        if raw_from_me is not None and from_me is None:
            return None
        raw_id = record.get("rowid")
        identifier = str(raw_id) if isinstance(raw_id, int) and not isinstance(raw_id, bool) else str(index + 1)
        if identifier in identifiers:
            return None
        identifiers.add(identifier)
        messages.append(ChatMessage(identifier, thread, sender, text, when,
                                    from_me))
    return tuple(threads.items()), tuple(messages), ()


def decode_chat_database(data: object, *, wal: object | None = None,
                         shm: object | None = None,
                         sidecars: Mapping[str, bytes] | None = None) -> ChatArchive | None:
    """Decode a checked generic, iOS Messages, or WhatsApp SQLite chat database."""
    checked_sidecars: dict[str, bytes] | None = None
    if sidecars is not None:
        items = _bounded_mapping_items(sidecars, MAX_PARTS)
        if items is None:
            return None
        total = 0
        checked_sidecars = {}
        for name, body in items:
            if not isinstance(name, str) or not name or len(name) > 4096 or not isinstance(body, bytes):
                return None
            if name in checked_sidecars:
                return None
            total += len(body)
            if len(body) > MAX_ATTACHMENT or total > MAX_TOTAL_ATTACHMENTS:
                return None
            checked_sidecars[name] = body
    # The -shm is only a volatile index cache for the WAL: SQLite rebuilds it from the committed
    # WAL frames, so it is never trusted as a source of row data.  We accept it (type-checked) for
    # API completeness but drive the overlay solely from the checksum-validated WAL below; the base
    # pages plus those committed frames are the only bytes any row is read from.
    if shm is not None and not isinstance(shm, (bytes, bytearray, memoryview)):
        return None
    bundle = _browser.validate_sqlite_bundle(data, wal=wal, shm=None)
    if bundle is None:
        return None
    raw, side_wal, frames = bundle
    try:
        db = _sqlite.Database(raw, side_wal, None, name="chat.sqlite", carve=False)
    except Exception:
        return None
    if db.error or db.truncated or not _chat_database_bounded(db):
        return None
    schema = _chat_schema(db)
    if schema == "ios_sms":
        parsed = _ios_chat(db, checked_sidecars)
    elif schema in {"whatsapp_msgstore_old", "whatsapp_msgstore_new"}:
        if checked_sidecars:
            return None
        parsed = _whatsapp_chat(db)
        schema = "whatsapp_msgstore"
    elif schema == "generic_chat":
        if checked_sidecars:
            return None
        parsed = _generic_chat(db)
    else:
        return None
    if parsed is None:
        return None
    threads, messages, attachments = parsed
    if not messages:
        return None
    return ChatArchive(schema, threads, messages, attachments, frames,
                       hashlib.sha256(raw).hexdigest())


__all__ = [
    "EmailObject", "EmailMessage", "EmailArtifact", "EmailThread", "ChatMessage",
    "ChatAttachment", "ChatArchive", "decode_email_artifact", "build_email_threads",
    "decode_chat_database",
]
