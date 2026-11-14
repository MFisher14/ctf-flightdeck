#!/usr/bin/env python3
"""Bounded, offline depth for Outlook stores and exported mail/chat archives.

This module intentionally composes the repository's existing parsers instead of
creating a second MIME or CFB implementation:

* :mod:`artifact_depth` remains the PST/OST NDB B-tree validator;
* :mod:`email_chat_forensics` remains the MSG/mbox decoder and RFC threader;
* this file adds a read-only libpff-style object adapter and static Slack,
  Discord, and Teams JSON-export normalization.

No URL is opened, no attachment is written, and HTML, macros, and embedded
objects are returned only as inert evidence.  Public functions either return a
result or raise :class:`MailDepthError`; dependency and stdlib exceptions never
cross that boundary.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import decimal
import functools
import hashlib
import io
import json
import math
import re
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:
    import artifact_depth as _artifact
    import email_chat_forensics as _mailchat
except ImportError:  # pragma: no cover - package-style import outside the flat test path
    from . import artifact_depth as _artifact
    from . import email_chat_forensics as _mailchat


MAX_INPUT = 256 << 20
MAX_JSON_FILE = 32 << 20
MAX_JSON_TOTAL = 128 << 20
MAX_ZIP_MEMBERS = 4096
MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 32
MAX_TEXT = 16 << 20
MAX_CHANNELS = 100_000
MAX_USERS = 250_000
MAX_MESSAGES = 250_000
MAX_ATTACHMENTS = 64
MAX_HISTORY = 256
MAX_PFF_FOLDERS = 100_000
MAX_PFF_MESSAGES = 250_000
MAX_PFF_DEPTH = 64
MAX_PFF_ATTACHMENTS = 100_000
MAX_ATTACHMENT = 64 << 20
MAX_ATTACHMENT_TOTAL = 256 << 20
PFF_MAGIC = b"!BDN"
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
PFF_ANSI_HEADER = 512
PFF_UNICODE_HEADER = 564
PFF_4K_VERSIONS = frozenset((36,))
FLAG_RE = flagfmt.TEXT
SLACK_TS = re.compile(r"[0-9]{1,20}(?:\.[0-9]{1,12})?")
UTC = dt.timezone.utc


class MailDepthError(ValueError):
    """The sole exception exposed by this engine's public parsing APIs."""


def _contract(function):
    """Translate every dependency/parser failure to the declared exception."""

    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MailDepthError:
            raise
        except Exception as exc:
            raise MailDepthError(f"{function.__name__}: malformed or unsupported input") from exc

    return guarded


def _bytes(value: object, *, cap: int = MAX_INPUT, label: str = "input") -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise MailDepthError(f"{label} must be bytes")
    if len(value) == 0 or len(value) > cap:
        raise MailDepthError(f"{label} is empty or exceeds its size cap")
    return bytes(value)


def _string(value: object, *, cap: int = MAX_TEXT, empty: bool = True) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > cap or "\x00" in value:
        raise MailDepthError("invalid or oversized text field")
    if not value and not empty:
        raise MailDepthError("required text field is empty")
    return value


def _identifier(value: object, *, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise MailDepthError("required identifier is absent")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise MailDepthError("identifier must be a string or integer")
    result = str(value)
    if not result or len(result) > 4096 or "\x00" in result:
        raise MailDepthError("invalid identifier")
    return result


def _flags(*values: object) -> list[str]:
    found: list[str] = []
    for value in values:
        if isinstance(value, str):
            for match in FLAG_RE.finditer(value):
                if match.group() not in found:
                    found.append(match.group())
    return found


def _iso(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = _string(value, cap=4096, empty=False)
    assert text is not None
    raw = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except (ValueError, OverflowError) as exc:
        raise MailDepthError("invalid ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise MailDepthError("timestamp lacks a UTC offset")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _slack_time(value: object) -> str:
    raw = _identifier(value)
    assert raw is not None
    if not SLACK_TS.fullmatch(raw):
        raise MailDepthError("invalid Slack timestamp")
    try:
        instant = decimal.Decimal(raw)
        seconds = int(instant)
        micros = int((instant - seconds) * 1_000_000)
        parsed = dt.datetime.fromtimestamp(seconds, UTC).replace(microsecond=micros)
    except (decimal.InvalidOperation, ValueError, OverflowError, OSError) as exc:
        raise MailDepthError("Slack timestamp is outside the supported range") from exc
    return parsed.isoformat().replace("+00:00", "Z")


def _mapping(value: object, *, label: str = "record") -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > MAX_JSON_NODES:
        raise MailDepthError(f"{label} is not a bounded object")
    if not all(isinstance(key, str) and len(key) <= 4096 and "\x00" not in key for key in value):
        raise MailDepthError(f"{label} contains an invalid key")
    return value


def _sequence(value: object, *, cap: int, label: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray, memoryview)):
        raise MailDepthError(f"{label} is not a sequence")
    if len(value) > cap:
        raise MailDepthError(f"{label} exceeds its item cap")
    return list(value)


def _first(record: Mapping[str, object], *names: str) -> object:
    for name in names:
        if name in record:
            return record[name]
    return None


def _json_bound(value: object) -> None:
    pending = [(value, 0)]
    seen = 0
    while pending:
        current, depth = pending.pop()
        seen += 1
        if seen > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise MailDepthError("JSON exceeds its node or nesting cap")
        if isinstance(current, str):
            if len(current) > MAX_TEXT or "\x00" in current:
                raise MailDepthError("JSON contains oversized or NUL text")
        elif current is None or isinstance(current, (bool, int)):
            continue
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise MailDepthError("JSON contains a non-finite number")
        elif isinstance(current, list):
            if len(current) > MAX_JSON_NODES:
                raise MailDepthError("JSON array exceeds its item cap")
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            if len(current) > MAX_JSON_NODES or not all(isinstance(key, str) for key in current):
                raise MailDepthError("JSON object is invalid or oversized")
            pending.extend((item, depth + 1) for item in current.values())
        else:
            raise MailDepthError("JSON contains an unsupported value")


def _json_load(raw: bytes, source: str) -> object:
    if not raw or len(raw) > MAX_JSON_FILE:
        raise MailDepthError(f"JSON member {source!r} is empty or oversized")
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MailDepthError(f"JSON member {source!r} contains a duplicate key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise MailDepthError(f"JSON member {source!r} contains a non-finite number")

    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=object_pairs,
                           parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MailDepthError(f"JSON member {source!r} is malformed") from exc
    _json_bound(value)
    return value


def _safe_member(name: object) -> str:
    text = _string(name, cap=8192, empty=False)
    assert text is not None
    text = text.replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise MailDepthError("archive contains an unsafe member path")
    return str(path)


def _export_files(value: object, *, name: str = "export.json") -> dict[str, object]:
    files: dict[str, object] = {}
    if isinstance(value, Mapping):
        if len(value) > MAX_ZIP_MEMBERS:
            raise MailDepthError("export mapping exceeds its file cap")
        total = 0
        for raw_name, body in value.items():
            path = _safe_member(raw_name)
            if path in files:
                raise MailDepthError("duplicate export member")
            if isinstance(body, (bytes, bytearray, memoryview)):
                raw = bytes(body)
                total += len(raw)
                if total > MAX_JSON_TOTAL:
                    raise MailDepthError("JSON export exceeds its aggregate cap")
                files[path] = _json_load(raw, path)
            elif isinstance(body, str):
                raw = body.encode("utf-8")
                total += len(raw)
                if total > MAX_JSON_TOTAL:
                    raise MailDepthError("JSON export exceeds its aggregate cap")
                files[path] = _json_load(raw, path)
            else:
                _json_bound(body)
                files[path] = body
        if not files:
            raise MailDepthError("export mapping is empty")
        return files

    raw = _bytes(value)
    if raw.startswith(b"PK\x03\x04"):
        total = 0
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ZIP_MEMBERS:
                    raise MailDepthError("ZIP export exceeds its member cap")
                for info in infos:
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue
                    path = _safe_member(info.filename)
                    if info.flag_bits & 1:
                        raise MailDepthError("encrypted JSON export member is unsupported")
                    if info.file_size <= 0 or info.file_size > MAX_JSON_FILE:
                        raise MailDepthError("ZIP JSON member is empty or oversized")
                    if info.compress_size and info.file_size > info.compress_size * 1000:
                        raise MailDepthError("ZIP JSON member exceeds compression-ratio cap")
                    total += info.file_size
                    if total > MAX_JSON_TOTAL:
                        raise MailDepthError("ZIP JSON members exceed aggregate cap")
                    if path in files:
                        raise MailDepthError("duplicate ZIP member")
                    files[path] = _json_load(archive.read(info), path)
        except MailDepthError:
            raise
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
            raise MailDepthError("invalid ZIP export") from exc
        if not files:
            raise MailDepthError("ZIP contains no JSON export members")
        return files
    path = _safe_member(name)
    return {path: _json_load(raw, path)}


# ---- PST/OST -------------------------------------------------------------------------------


def _pff_header(data: object, name: object) -> tuple[bytes, str, bytes, int]:
    """Return bounded PFF header facts without claiming NDB-tree validity."""

    raw = _bytes(data)
    label = _string(name, cap=4096, empty=False)
    assert label is not None
    if len(raw) < PFF_ANSI_HEADER or raw[:4] != PFF_MAGIC:
        raise MailDepthError("not a PST/OST PFF file")
    client = raw[8:10]
    if client not in (b"SM", b"SO"):
        raise MailDepthError("unsupported PFF client signature")
    version = int.from_bytes(raw[10:12], "little")
    if version not in (14, 15, 23, 36, 37):
        raise MailDepthError("unsupported PFF NDB version")
    if version >= 23 and len(raw) < PFF_UNICODE_HEADER:
        raise MailDepthError("Unicode PFF header is truncated")
    return raw, label, client, version


def _pff_4k_profile(raw: bytes, client: bytes, version: int) -> dict[str, object]:
    """Facts safe to report only after libpff has accepted a 4-KiB-page PFF."""

    return {
        "format": "ost" if client == b"SO" else "pst",
        "client_signature": client.decode("ascii"),
        "client_magic": client.decode("ascii"),
        "ndb_version": version,
        "client_version": int.from_bytes(raw[12:14], "little"),
        "unicode": True,
        "page_size": 4096,
        "file_size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "trees": None,
        "ndb_validation": "libpff",
        "messaging_layer": "read-only libpff adapter",
    }


@_contract
def inspect_pff(data: object, name: str = "archive.pst") -> dict[str, object]:
    """Validate a PST/OST NDB through ``artifact_depth`` and return its profile.

    ``artifact_depth`` historically accepts the PST client marker ``SM`` only.
    Native OST's documented ``SO`` marker is changed only in a private validation
    copy; all offsets, pages, CRCs, BIDs, and returned SHA-256 remain those of the
    caller's original bytes.
    """

    raw, label, client, version = _pff_header(data, name)
    if version in PFF_4K_VERSIONS:
        raise MailDepthError(
            "4-KiB-page PFF requires analyze_pff_path with a libpff backend"
        )
    proxy = raw if client == b"SM" else raw[:8] + b"SM" + raw[10:]
    try:
        profile = dict(_artifact.inspect_pst_ost(proxy, label))
    except _artifact.ArtifactError as exc:
        raise MailDepthError(str(exc)) from exc
    profile.update({
        "format": "ost" if client == b"SO" else "pst",
        "client_signature": client.decode("ascii"),
        "client_magic": client.decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "messaging_layer": "requires read-only libpff-style adapter",
    })
    if "trees" not in profile and "ndb_trees" in profile:
        profile["trees"] = profile["ndb_trees"]
    return profile


def _pff_value(obj: object, names: tuple[str, ...], default: object = None) -> object:
    for name in names:
        try:
            return getattr(obj, name)
        except (AttributeError, NotImplementedError):
            continue
        except Exception as exc:
            raise MailDepthError(f"libpff property {name!r} failed") from exc
    return default


def _pff_count(obj: object, names: tuple[str, ...], *, cap: int, label: str) -> int:
    value = _pff_value(obj, names, 0)
    if callable(value):
        try:
            value = value()
        except Exception as exc:
            raise MailDepthError(f"libpff {label} count lookup failed") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= cap:
        raise MailDepthError(f"invalid libpff {label} count")
    return value


def _pff_text(value: object, *, cap: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _string(value, cap=cap)
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) > cap:
        raise MailDepthError("invalid libpff text value")
    raw = bytes(value).rstrip(b"\x00")
    if not raw:
        return ""
    encodings = ("utf-16-le", "utf-8", "cp1252") if raw[1:2] == b"\x00" else ("utf-8", "utf-16-le", "cp1252")
    for encoding in encodings:
        try:
            text = raw.decode(encoding)
            if "\x00" not in text:
                return text
        except (UnicodeDecodeError, UnicodeError):
            continue
    raise MailDepthError("libpff text has no supported encoding")


def _pff_id(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        if len(value) > 4096:
            raise MailDepthError("libpff identifier exceeds cap")
        return bytes(value).hex()
    return _identifier(value, required=False)


def _pff_time(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return _pff_text(value, cap=4096)


def _pff_record_value(item: object, tags: tuple[int, ...], names: tuple[str, ...]) -> object:
    """Read one MAPI value from a current pypff ``record_set`` object."""

    getter = _pff_value(item, ("get_entry_by_type",), None)
    if not callable(getter):
        return None
    for tag in tags:
        try:
            entry = getter(tag)
        except Exception as exc:
            raise MailDepthError("libpff recipient property lookup failed") from exc
        if entry is None:
            continue
        value = _pff_value(entry, names, None)
        if callable(value):
            try:
                value = value()
            except Exception as exc:
                raise MailDepthError("libpff recipient property decoding failed") from exc
        if value is not None:
            return value
    return None


def _pff_attachment(item: object, state: dict[str, int]) -> dict[str, object]:
    state["attachment_count"] += 1
    if state["attachment_count"] > MAX_PFF_ATTACHMENTS:
        raise MailDepthError("libpff attachment count exceeds cap")
    filename = _pff_text(_pff_value(item, ("long_filename", "filename", "name")), cap=4096)
    media = _pff_text(_pff_value(item, ("mime_type", "media_type")), cap=256)
    declared = _pff_value(item, ("size", "data_size"), None)
    if declared is None:
        raise MailDepthError("libpff attachment does not declare its size")
    if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
        raise MailDepthError("invalid libpff attachment size")
    result: dict[str, object] = {"filename": filename, "media_type": media, "size": declared,
                                "data": None, "sha256": None}
    if declared > MAX_ATTACHMENT:
        result["omitted"] = "attachment exceeds per-item byte cap"
        return result
    if state["attachment_bytes"] + declared > MAX_ATTACHMENT_TOTAL:
        result["omitted"] = "aggregate attachment byte cap reached"
        return result
    reader = _pff_value(item, ("read_buffer",), None)
    if not callable(reader):
        raise MailDepthError("libpff attachment has no read_buffer method")
    try:
        body = reader(declared)
    except Exception as exc:
        raise MailDepthError("libpff attachment read failed") from exc
    if not isinstance(body, (bytes, bytearray, memoryview)) or len(body) != declared:
        raise MailDepthError("libpff attachment size mismatch")
    data = bytes(body)
    state["attachment_bytes"] += len(data)
    result.update({"data": data, "sha256": hashlib.sha256(data).hexdigest()})
    return result


def _pff_message(item: object, state: dict[str, int]) -> dict[str, object]:
    state["message_count"] += 1
    if state["message_count"] > MAX_PFF_MESSAGES:
        raise MailDepthError("libpff message count exceeds cap")
    bodies = {}
    for output, names in (
        ("plain", ("plain_text_body",)),
        ("html", ("html_body",)),
        ("rtf", ("rtf_body", "compressed_rtf_body")),
    ):
        value = _pff_value(item, names)
        if value is not None:
            bodies[output] = _pff_text(value)
    attachments = []
    count = _pff_count(item, ("number_of_attachments", "get_number_of_attachments"),
                       cap=MAX_ATTACHMENTS, label="message attachment")
    getter = _pff_value(item, ("get_attachment",), None)
    if count and not callable(getter):
        raise MailDepthError("libpff message lacks get_attachment")
    for index in range(count):
        try:
            attachment = getter(index)
        except Exception as exc:
            raise MailDepthError("libpff attachment lookup failed") from exc
        if attachment is None:
            raise MailDepthError("libpff attachment lookup returned nothing")
        attachments.append(_pff_attachment(attachment, state))

    recipients = []
    recipient_source = _pff_value(item, ("recipients",), None)
    if recipient_source is None:
        # Older/test adapters sometimes expose the recipient table directly on
        # the message; current pypff exposes a nested ``recipients`` object.
        recipient_source = item
    recipient_count = _pff_count(recipient_source,
                                 ("number_of_recipients", "get_number_of_recipients"),
                                 cap=4096, label="recipient")
    recipient_getter = _pff_value(recipient_source, ("get_recipient",), None)
    if recipient_count and not callable(recipient_getter):
        raise MailDepthError("libpff message lacks get_recipient")
    for index in range(recipient_count):
        try:
            recipient = recipient_getter(index)
        except Exception as exc:
            raise MailDepthError("libpff recipient lookup failed") from exc
        recipient_name = _pff_value(recipient, ("display_name", "name"))
        if recipient_name is None:
            recipient_name = _pff_record_value(
                recipient, (0x3001,), ("data_as_string", "get_data_as_string")
            )
        recipient_email = _pff_value(recipient, ("email_address", "address"))
        if recipient_email is None:
            recipient_email = _pff_record_value(
                recipient, (0x39FE, 0x3003), ("data_as_string", "get_data_as_string")
            )
        recipient_type = _pff_value(recipient, ("recipient_type", "type"))
        if recipient_type is None:
            recipient_type = _pff_record_value(
                recipient, (0x0C15,), ("data_as_integer", "get_data_as_integer")
            )
        if recipient_type is not None and (
                isinstance(recipient_type, bool) or not isinstance(recipient_type, (str, int))):
            raise MailDepthError("invalid libpff recipient type")
        recipients.append({
            "name": _pff_text(recipient_name, cap=4096),
            "email": _pff_text(recipient_email, cap=4096),
            "type": str(recipient_type) if recipient_type is not None else None,
        })

    record = {
        "id": _pff_id(_pff_value(item, ("identifier", "entry_identifier", "record_key"))),
        "subject": _pff_text(_pff_value(item, ("subject",))),
        "sender_name": _pff_text(_pff_value(item, ("sender_name",)), cap=4096),
        "sender_email": _pff_text(_pff_value(item, ("sender_email_address", "sender_email")), cap=4096),
        "transport_headers": _pff_text(_pff_value(item, ("transport_headers",))),
        "display_to": _pff_text(_pff_value(item, ("display_to",)), cap=MAX_TEXT),
        "delivery_time": _pff_time(_pff_value(item, ("delivery_time", "client_submit_time"))),
        "bodies": bodies,
        "recipients": recipients,
        "attachments": attachments,
    }
    record["flags"] = _flags(record["subject"], record["transport_headers"], *bodies.values())
    return record


@_contract
def extract_pff_store(root_folder: object) -> dict[str, object]:
    """Traverse a supplied read-only libpff-style root folder.

    The accepted interface follows pypff: folder count properties plus
    ``get_sub_folder``/``get_sub_message``; messages expose body/header fields
    and ``get_attachment``.  The function is intentionally injectable so tests
    and environments without native libpff can use documented object fixtures.
    """

    if root_folder is None:
        raise MailDepthError("libpff root folder is absent")
    state = {"folder_count": 0, "message_count": 0, "attachment_count": 0, "attachment_bytes": 0}
    active: set[int] = set()

    def folder(item: object, path: tuple[str, ...], depth: int) -> dict[str, object]:
        if depth > MAX_PFF_DEPTH:
            raise MailDepthError("libpff folder depth exceeds cap")
        marker = id(item)
        if marker in active:
            raise MailDepthError("libpff folder graph contains a cycle")
        active.add(marker)
        state["folder_count"] += 1
        if state["folder_count"] > MAX_PFF_FOLDERS:
            raise MailDepthError("libpff folder count exceeds cap")
        name = _pff_text(_pff_value(item, ("name", "display_name")), cap=4096) or ""
        here = path + (name,)
        message_count = _pff_count(item, ("number_of_sub_messages", "number_of_messages", "get_number_of_sub_messages"),
                                   cap=MAX_PFF_MESSAGES, label="folder message")
        message_getter = _pff_value(item, ("get_sub_message", "get_message"), None)
        if message_count and not callable(message_getter):
            raise MailDepthError("libpff folder lacks message getter")
        messages = []
        for index in range(message_count):
            try:
                message = message_getter(index)
            except Exception as exc:
                raise MailDepthError("libpff message lookup failed") from exc
            if message is None:
                raise MailDepthError("libpff message lookup returned nothing")
            message_record = _pff_message(message, state)
            message_record["folder"] = "/".join(part for part in here if part)
            message_record["plain_body"] = message_record["bodies"].get("plain")
            message_record["html_body"] = message_record["bodies"].get("html")
            message_record["rtf_body"] = message_record["bodies"].get("rtf")
            messages.append(message_record)
        folder_count = _pff_count(item, ("number_of_sub_folders", "get_number_of_sub_folders"),
                                  cap=MAX_PFF_FOLDERS, label="subfolder")
        folder_getter = _pff_value(item, ("get_sub_folder",), None)
        if folder_count and not callable(folder_getter):
            raise MailDepthError("libpff folder lacks subfolder getter")
        children = []
        for index in range(folder_count):
            try:
                child = folder_getter(index)
            except Exception as exc:
                raise MailDepthError("libpff folder lookup failed") from exc
            if child is None:
                raise MailDepthError("libpff folder lookup returned nothing")
            children.append(folder(child, here, depth + 1))
        active.remove(marker)
        return {"name": name, "path": "/".join(part for part in here if part),
                "identifier": _pff_id(_pff_value(item, ("identifier", "entry_identifier"))),
                "messages": messages, "folders": children}

    root = folder(root_folder, (), 0)
    flat_messages: list[dict[str, object]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        flat_messages.extend(current["messages"])
        pending.extend(reversed(current["folders"]))
    return {
        "format": "pff-message-store",
        "root": root,
        "counts": dict(state),
        "folder_count": state["folder_count"],
        "message_count": state["message_count"],
        "attachment_count": state["attachment_count"],
        "attachment_bytes": state["attachment_bytes"],
        "messages": flat_messages,
    }


@_contract
def analyze_pff_path(path: str | Path, *, pypff_module: object | None = None) -> dict[str, object]:
    """Profile a PST/OST path and, when available, traverse it via read-only pypff."""

    source = Path(path)
    try:
        with source.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
    except OSError as exc:
        raise MailDepthError("PFF path could not be read") from exc
    if len(raw) > MAX_INPUT:
        raise MailDepthError("PFF file exceeds size cap")
    raw, _label, client, version = _pff_header(raw, source.name)
    requires_libpff = version in PFF_4K_VERSIONS
    profile = None if requires_libpff else inspect_pff(raw, source.name)
    module = pypff_module
    if module is None:
        try:
            import pypff as module  # type: ignore[import-not-found]
        except ImportError:
            if requires_libpff:
                raise MailDepthError("4-KiB-page PFF requires the optional pypff backend")
            return {"profile": profile, "backend": "unavailable", "store": None}
    factory = getattr(module, "file", None)
    if not callable(factory):
        raise MailDepthError("pypff module has no file factory")
    handle = None
    try:
        handle = factory()
        opener = getattr(handle, "open", None)
        if not callable(opener):
            raise MailDepthError("pypff file object has no open method")
        opener(str(source))
        root = getattr(handle, "root_folder")
        store = extract_pff_store(root)
    except MailDepthError:
        raise
    except Exception as exc:
        raise MailDepthError("pypff could not read the PFF message store") from exc
    finally:
        if handle is not None:
            closer = getattr(handle, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass
    if profile is None:
        # The local NDB walker is intentionally not used for v36/v37: it is a
        # 512-byte-page implementation.  Successful libpff open/traversal is
        # the validation boundary for compressed 4-KiB-page stores.
        profile = _pff_4k_profile(raw, client, version)
    return {"profile": profile, "backend": "pypff", "store": store}


# ---- Existing MSG/mbox composition ----------------------------------------------------------


def _plain_record(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return {field.name: _plain_record(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _plain_record(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_record(item) for item in value]
    return value


def _email_message_record(value: object) -> dict[str, object]:
    """Expose the existing decoder's message dataclass as a stable JSON shape."""

    plain = _plain_record(value)
    if not isinstance(plain, dict):
        raise MailDepthError("existing email decoder returned an invalid message")
    if not isinstance(plain.get("bodies"), list):
        raise MailDepthError("existing email decoder returned invalid bodies")
    for body in plain["bodies"]:
        if not isinstance(body, list) or len(body) != 2:
            raise MailDepthError("existing email decoder returned an invalid body")
    if not isinstance(plain.get("objects"), list):
        raise MailDepthError("existing email decoder returned invalid attachments")
    return plain


def _email_artifact_record(artifact: object) -> dict[str, object]:
    kind = getattr(artifact, "kind", None)
    digest = getattr(artifact, "sha256", None)
    messages = getattr(artifact, "messages", None)
    if not isinstance(kind, str) or not isinstance(digest, str) or not isinstance(messages, tuple):
        raise MailDepthError("existing email decoder returned an invalid artifact")
    return {"kind": kind, "messages": [_email_message_record(message) for message in messages],
            "sha256": digest}


@_contract
def analyze_msg(data: object, name: str = "message.msg") -> dict[str, object]:
    raw = _bytes(data)
    label = _string(name, cap=4096, empty=False)
    assert label is not None
    if not raw.startswith(CFB_MAGIC):
        raise MailDepthError("not a CFB/MSG file")
    artifact = _mailchat.decode_email_artifact(raw, name=label)
    if artifact is None or artifact.kind != "msg":
        raise MailDepthError("MSG did not pass the existing strict decoder")
    result = _email_artifact_record(artifact)
    result["format"] = "msg"
    result["parser"] = "email_chat_forensics"
    return result


@_contract
def analyze_mbox(data: object, name: str = "mailbox.mbox") -> dict[str, object]:
    raw = _bytes(data)
    label = _string(name, cap=4096, empty=False)
    assert label is not None
    artifact = _mailchat.decode_email_artifact(raw, name=label)
    if artifact is None or artifact.kind != "mbox":
        raise MailDepthError("mbox did not pass the existing strict decoder")
    threads = _mailchat.build_email_threads({label: raw})
    if threads is None:
        raise MailDepthError("mbox thread graph is ambiguous or malformed")
    artifact_record = _email_artifact_record(artifact)
    thread_records = []
    for thread in threads:
        thread_records.append({
            "root_id": thread.root_id,
            "message_ids": list(thread.message_ids),
            "edges": [list(edge) for edge in thread.edges],
        })
    return {"format": "mbox", "parser": "email_chat_forensics",
            "artifact": artifact_record, "messages": artifact_record["messages"],
            "threads": thread_records}


# ---- Export attachment/message normalization ------------------------------------------------


def _attachment(record: object) -> dict[str, object]:
    if isinstance(record, str):
        url = _string(record, cap=MAX_TEXT, empty=False)
        return {"id": None, "name": None, "media_type": None, "size": None, "url": url}
    item = _mapping(record, label="attachment")
    size = _first(item, "size", "Size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise MailDepthError("attachment metadata has an invalid size")
    return {
        "id": _identifier(_first(item, "id", "ID"), required=False),
        "name": _string(_first(item, "name", "filename", "title", "Name"), cap=4096),
        "media_type": _string(_first(item, "mimetype", "mime_type", "contentType", "content_type"), cap=4096),
        "size": size,
        "url": _string(_first(item, "url_private", "url_private_download", "url", "proxy_url", "contentUrl", "URL")),
    }


def _attachments(value: object) -> list[dict[str, object]]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        values: list[object] = [line for line in value.splitlines() if line.strip()]
    else:
        values = _sequence(value, cap=MAX_ATTACHMENTS, label="attachments")
    return [_attachment(item) for item in values]


def _reactions(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    rows = _sequence(value, cap=MAX_HISTORY, label="reactions")
    result = []
    for row in rows:
        item = _mapping(row, label="reaction")
        result.append({str(key): _plain_record(val) for key, val in item.items()
                       if key in {"name", "type", "count", "users", "user", "createdDateTime", "reactionType"}})
    return result


def _merge_message(messages: dict[tuple[str, str], dict[str, object]], record: dict[str, object]) -> None:
    key = (str(record["conversation_id"]), str(record["id"]))
    old = messages.get(key)
    if old is None:
        if len(messages) >= MAX_MESSAGES:
            raise MailDepthError("message count exceeds cap")
        messages[key] = record
        return
    # Audit/edit exports legitimately repeat a message. Merge only the evidence
    # fields; conflicting immutable creation/sender data is corruption.
    for field in ("created_raw", "sender_id"):
        if old.get(field) not in (None, record.get(field)) and record.get(field) is not None:
            raise MailDepthError("conflicting duplicate message record")
    if record.get("edited"):
        old["edited"], old["edited_raw"] = record["edited"], record.get("edited_raw")
    if record.get("deleted"):
        old["deleted"] = True
    if record.get("text") not in (None, ""):
        old["text"] = record["text"]
    old["edit_history"] = list(old.get("edit_history") or []) + list(record.get("edit_history") or [])
    old["flags"] = _flags(*(list(old.get("flags") or []) + list(record.get("flags") or [])))
    old["sources"] = list(dict.fromkeys(list(old.get("sources") or []) + list(record.get("sources") or [])))


def _final(platform: str, users: list[dict[str, object]], channels: list[dict[str, object]],
           messages: dict[tuple[str, str], dict[str, object]]) -> dict[str, object]:
    ordered = sorted(messages.values(), key=lambda row: (str(row.get("created") or ""),
                                                         str(row.get("conversation_id")), str(row.get("id"))))
    return {"platform": platform, "users": users, "channels": channels, "messages": ordered,
            "counts": {"users": len(users), "channels": len(channels), "messages": len(ordered),
                       "attachments": sum(len(row.get("attachments") or []) for row in ordered),
                       "edited": sum(bool(row.get("edited")) for row in ordered),
                       "deleted": sum(bool(row.get("deleted")) for row in ordered)},
            "flags": list(dict.fromkeys(flag for row in ordered for flag in row.get("flags", [])))}


def _manifest(files: Mapping[str, object], basename: str) -> object | None:
    found = [value for path, value in files.items() if PurePosixPath(path).name.lower() == basename.lower()]
    if len(found) > 1:
        raise MailDepthError(f"export contains multiple {basename} manifests")
    return found[0] if found else None


def _slack_files(files: Mapping[str, object]) -> dict[str, object]:
    users: list[dict[str, object]] = []
    user_names: dict[str, str] = {}
    raw_users = _manifest(files, "users.json")
    if raw_users is not None:
        for raw in _sequence(raw_users, cap=MAX_USERS, label="Slack users"):
            item = _mapping(raw, label="Slack user")
            identifier = _identifier(item.get("id"))
            profile = item.get("profile") if isinstance(item.get("profile"), Mapping) else {}
            display = _first(profile, "display_name", "real_name") or _first(item, "real_name", "name")
            display = _string(display, cap=4096)
            assert identifier is not None
            if identifier in user_names:
                raise MailDepthError("duplicate Slack user ID")
            user_names[identifier] = display or identifier
            users.append({"id": identifier, "name": _string(item.get("name"), cap=4096), "display_name": display})

    channels: list[dict[str, object]] = []
    by_folder: dict[str, dict[str, object]] = {}
    by_channel: dict[str, dict[str, object]] = {}
    for manifest_name, kind in (("channels.json", "channel"), ("groups.json", "private"),
                                ("dms.json", "dm"), ("mpims.json", "group_dm")):
        raw_manifest = _manifest(files, manifest_name)
        if raw_manifest is None:
            continue
        for raw in _sequence(raw_manifest, cap=MAX_CHANNELS, label="Slack channels"):
            item = _mapping(raw, label="Slack channel")
            identifier = _identifier(item.get("id"))
            assert identifier is not None
            name = _string(item.get("name"), cap=4096) or identifier
            if identifier in by_channel:
                raise MailDepthError("duplicate Slack channel ID")
            record = {"id": identifier, "name": name, "kind": kind,
                      "members": [_identifier(member) for member in _sequence(item.get("members", []), cap=MAX_USERS,
                                                                                label="Slack channel members")]}
            by_channel[identifier] = record
            by_folder[name] = record
            channels.append(record)

    messages: dict[tuple[str, str], dict[str, object]] = {}
    manifests = {"users.json", "channels.json", "groups.json", "dms.json", "mpims.json",
                 "org_users.json", "integration_logs.json", "content_flags.json", "canvases.json"}
    for path, payload in files.items():
        if PurePosixPath(path).name.lower() in manifests:
            continue
        if not isinstance(payload, list):
            continue
        parent = PurePosixPath(path).parent.name or "unknown"
        channel = by_folder.get(parent) or by_channel.get(parent)
        if channel is None:
            identifier = parent
            channel = {"id": identifier, "name": parent, "kind": "unknown", "members": []}
            by_channel[identifier] = channel
            by_folder[parent] = channel
            channels.append(channel)
        for raw in _sequence(payload, cap=MAX_MESSAGES, label="Slack messages"):
            item = _mapping(raw, label="Slack message")
            if item.get("type") not in (None, "message"):
                continue
            subtype = _string(item.get("subtype"), cap=4096)
            previous = item.get("previous") if subtype in {"message_changed", "message_deleted"} else None
            if previous is not None:
                previous = _mapping(previous, label="Slack previous message")
            if subtype == "message_changed":
                current = item.get("message")
            elif subtype == "message_deleted" and previous is not None:
                current = previous
            else:
                current = item
            current = _mapping(current, label="Slack current message")
            raw_ts = _first(current, "ts", "original_ts") or _first(item, "deleted_ts", "original_ts", "ts")
            identifier = _identifier(raw_ts)
            assert identifier is not None
            created_raw = _identifier(_first(previous or {}, "ts") or _first(current, "ts") or raw_ts)
            assert created_raw is not None
            sender = _identifier(_first(current, "user") or _first(previous or {}, "user") or item.get("user"), required=False)
            text = _string(_first(current, "text") if "text" in current else _first(previous or {}, "text"))
            edited_info = current.get("edited") if isinstance(current.get("edited"), Mapping) else {}
            edited_raw = _first(edited_info, "ts") or (item.get("ts") if subtype == "message_changed" else None)
            parent_id = _identifier(current.get("thread_ts"), required=False)
            if parent_id == identifier:
                parent_id = None
            files_meta = _attachments(current.get("files")) + _attachments(current.get("attachments"))
            history = []
            if previous is not None:
                history.append({"text": _string(previous.get("text")), "ts": _identifier(previous.get("ts"), required=False)})
            record = {
                "id": identifier, "conversation_id": channel["id"], "conversation_name": channel["name"],
                "sender_id": sender, "sender_name": user_names.get(sender or ""),
                "created_raw": created_raw, "created": _slack_time(created_raw),
                "edited_raw": _identifier(edited_raw, required=False),
                "edited": _slack_time(edited_raw) if edited_raw is not None else None,
                "deleted": subtype == "message_deleted" or subtype == "tombstone",
                "parent_id": parent_id, "text": text, "body_format": "mrkdwn",
                "attachments": files_meta, "reactions": _reactions(current.get("reactions")),
                "edit_history": history, "subtype": subtype, "sources": [path],
                "flags": _flags(text, *(entry.get("text") for entry in history),
                                  *(entry.get("name") for entry in files_meta)),
            }
            _merge_message(messages, record)
    if not messages:
        raise MailDepthError("no Slack messages found")
    return _final("slack", users, channels, messages)


def _discord_records(payload: object) -> list[object]:
    if isinstance(payload, list):
        return _sequence(payload, cap=MAX_MESSAGES, label="Discord messages")
    if isinstance(payload, Mapping):
        for key in ("messages", "Messages", "value"):
            if key in payload:
                return _sequence(payload[key], cap=MAX_MESSAGES, label="Discord messages")
    return []


def _discord_files(files: Mapping[str, object]) -> dict[str, object]:
    index = _manifest(files, "index.json")
    names: dict[str, str] = {}
    if isinstance(index, Mapping):
        for key, value in index.items():
            identifier = _identifier(key)
            name = value.get("name") if isinstance(value, Mapping) else value
            text = _string(name, cap=4096)
            assert identifier is not None
            if text is not None:
                names[identifier] = text
    channels_by_id: dict[str, dict[str, object]] = {}
    for path, payload in files.items():
        if PurePosixPath(path).name.lower() not in {"channel.json", "channel_metadata.json"}:
            continue
        item = _mapping(payload, label="Discord channel metadata")
        folder = PurePosixPath(path).parent.name
        fallback = folder[1:] if folder[:1].lower() == "c" and folder[1:].isdigit() else folder
        identifier = _identifier(_first(item, "id", "ID", "channel_id", "Channel ID") or fallback)
        assert identifier is not None
        name = _string(_first(item, "name", "Name"), cap=4096) or names.get(identifier) or identifier
        channels_by_id[identifier] = {"id": identifier, "name": name, "kind": _string(_first(item, "type", "Type"), cap=256),
                                      "members": _plain_record(_first(item, "recipients", "Recipients") or [])}
    messages: dict[tuple[str, str], dict[str, object]] = {}
    for path, payload in files.items():
        if PurePosixPath(path).name.lower() not in {"messages.json", "message.json"} and not (
                len(files) == 1 and _discord_records(payload)):
            continue
        folder = PurePosixPath(path).parent.name
        folder_id = folder[1:] if folder[:1].lower() == "c" and folder[1:].isdigit() else folder
        for raw in _discord_records(payload):
            item = _mapping(raw, label="Discord message")
            identifier = _identifier(_first(item, "id", "ID"))
            assert identifier is not None
            conversation = _identifier(_first(item, "channel_id", "Channel ID") or folder_id or "unknown")
            assert conversation is not None
            if conversation not in channels_by_id:
                channels_by_id[conversation] = {"id": conversation, "name": names.get(conversation, conversation),
                                                "kind": None, "members": []}
            timestamp_raw = _first(item, "timestamp", "Timestamp")
            timestamp_text = _string(timestamp_raw, cap=4096, empty=False)
            assert timestamp_text is not None
            author = item.get("author") if isinstance(item.get("author"), Mapping) else {}
            sender = _identifier(_first(author, "id", "ID") or _first(item, "author_id", "Author ID"), required=False)
            sender_name = _string(_first(author, "global_name", "display_name", "username", "name"), cap=4096)
            text = _string(_first(item, "content", "Contents", "text"))
            attachment_meta = _attachments(_first(item, "attachments", "Attachments"))
            reference = item.get("message_reference") if isinstance(item.get("message_reference"), Mapping) else {}
            embedded = item.get("referenced_message") if isinstance(item.get("referenced_message"), Mapping) else {}
            parent = _identifier(_first(reference, "message_id", "id") or _first(embedded, "id", "ID"), required=False)
            edited_raw = _first(item, "edited_timestamp", "Edited Timestamp")
            record = {
                "id": identifier, "conversation_id": conversation,
                "conversation_name": channels_by_id[conversation]["name"], "sender_id": sender,
                "sender_name": sender_name, "created_raw": timestamp_text, "created": _iso(timestamp_text),
                "edited_raw": _string(edited_raw, cap=4096), "edited": _iso(edited_raw),
                "deleted": bool(_first(item, "deleted", "Deleted")), "parent_id": parent,
                "text": text, "body_format": "discord-markdown", "attachments": attachment_meta,
                "reactions": _reactions(item.get("reactions")), "edit_history": [], "sources": [path],
                "flags": _flags(text, *(entry.get("name") for entry in attachment_meta)),
            }
            _merge_message(messages, record)
    if not messages:
        raise MailDepthError("no Discord messages found")
    return _final("discord", [], list(channels_by_id.values()), messages)


def _teams_records(payload: object) -> list[object]:
    if isinstance(payload, list):
        return _sequence(payload, cap=MAX_MESSAGES, label="Teams messages")
    if isinstance(payload, Mapping):
        for key in ("value", "messages", "retainedMessages"):
            if key in payload:
                return _sequence(payload[key], cap=MAX_MESSAGES, label="Teams messages")
        if "id" in payload and ("body" in payload or "createdDateTime" in payload):
            return [payload]
    return []


def _teams_files(files: Mapping[str, object]) -> dict[str, object]:
    channels: dict[str, dict[str, object]] = {}
    users: dict[str, dict[str, object]] = {}
    messages: dict[tuple[str, str], dict[str, object]] = {}
    for path, payload in files.items():
        records = _teams_records(payload)
        if not records:
            continue
        for raw in records:
            item = _mapping(raw, label="Teams message")
            identifier = _identifier(item.get("id"))
            assert identifier is not None
            channel_identity = item.get("channelIdentity") if isinstance(item.get("channelIdentity"), Mapping) else {}
            conversation = _identifier(item.get("chatId") or channel_identity.get("channelId") or "unknown")
            assert conversation is not None
            if conversation not in channels:
                channels[conversation] = {"id": conversation,
                                          "name": _string(item.get("subject"), cap=4096) or conversation,
                                          "kind": "channel" if channel_identity else "chat",
                                          "team_id": _identifier(channel_identity.get("teamId"), required=False),
                                          "members": []}
            sender_set = item.get("from") if isinstance(item.get("from"), Mapping) else {}
            identity: Mapping[str, object] = {}
            for kind in ("user", "application", "device", "conversation"):
                if isinstance(sender_set.get(kind), Mapping):
                    identity = sender_set[kind]
                    break
            sender = _identifier(identity.get("id"), required=False)
            sender_name = _string(identity.get("displayName"), cap=4096)
            if sender is not None:
                existing = users.get(sender)
                if existing and existing.get("display_name") not in (None, sender_name):
                    raise MailDepthError("conflicting Teams sender identity")
                users[sender] = {"id": sender, "name": None, "display_name": sender_name}
            body = item.get("body") if isinstance(item.get("body"), Mapping) else {}
            text = _string(body.get("content"))
            body_format = _string(body.get("contentType"), cap=256) or "text"
            created_raw = _string(item.get("createdDateTime"), cap=4096, empty=False)
            if created_raw is None:
                raise MailDepthError("Teams message lacks createdDateTime")
            edited_raw = _string(item.get("lastEditedDateTime"), cap=4096)
            deleted_raw = _string(item.get("deletedDateTime"), cap=4096)
            history_rows = []
            if item.get("messageHistory") is not None:
                for history in _sequence(item.get("messageHistory"), cap=MAX_HISTORY, label="Teams message history"):
                    history_rows.append(_plain_record(_mapping(history, label="Teams history record")))
            attachment_meta = _attachments(item.get("attachments"))
            record = {
                "id": identifier, "conversation_id": conversation,
                "conversation_name": channels[conversation]["name"], "sender_id": sender,
                "sender_name": sender_name, "created_raw": created_raw, "created": _iso(created_raw),
                "edited_raw": edited_raw, "edited": _iso(edited_raw), "deleted": deleted_raw is not None,
                "deleted_raw": deleted_raw, "parent_id": _identifier(item.get("replyToId"), required=False),
                "text": text, "body_format": body_format, "attachments": attachment_meta,
                "reactions": _reactions(item.get("reactions")), "edit_history": history_rows,
                "message_type": _string(item.get("messageType"), cap=256), "sources": [path],
                "flags": _flags(text, *(entry.get("name") for entry in attachment_meta),
                                  *(json.dumps(entry, sort_keys=True) for entry in history_rows)),
            }
            _merge_message(messages, record)
    if not messages:
        raise MailDepthError("no Teams messages found")
    return _final("teams", list(users.values()), list(channels.values()), messages)


@_contract
def parse_slack_export(data: object, *, name: str = "slack-export.json") -> dict[str, object]:
    return _slack_files(_export_files(data, name=name))


@_contract
def parse_discord_export(data: object, *, name: str = "discord-export.json") -> dict[str, object]:
    return _discord_files(_export_files(data, name=name))


@_contract
def parse_teams_export(data: object, *, name: str = "teams-export.json") -> dict[str, object]:
    return _teams_files(_export_files(data, name=name))


def _detect_chat(files: Mapping[str, object]) -> str:
    basenames = {PurePosixPath(path).name.lower() for path in files}
    if basenames & {"users.json", "channels.json", "groups.json", "dms.json", "mpims.json"}:
        return "slack"
    for payload in files.values():
        for record in _teams_records(payload)[:3]:
            if isinstance(record, Mapping) and ("createdDateTime" in record or "channelIdentity" in record):
                return "teams"
    if basenames & {"channel.json", "channel_metadata.json", "messages.json"}:
        return "discord"
    for payload in files.values():
        for record in _discord_records(payload)[:3]:
            if isinstance(record, Mapping) and ({"Timestamp", "Contents"} & set(record) or "timestamp" in record):
                return "discord"
        if isinstance(payload, list) and any(isinstance(record, Mapping) and "ts" in record for record in payload[:3]):
            return "slack"
    raise MailDepthError("could not identify chat export platform")


@_contract
def parse_chat_export(data: object, *, platform: str = "auto", name: str = "export.json") -> dict[str, object]:
    if platform not in {"auto", "slack", "discord", "teams"}:
        raise MailDepthError("unsupported chat export platform")
    files = _export_files(data, name=name)
    selected = _detect_chat(files) if platform == "auto" else platform
    return {"slack": _slack_files, "discord": _discord_files, "teams": _teams_files}[selected](files)


# ---- Unified API and CLI --------------------------------------------------------------------


@_contract
def analyze_bytes(data: object, *, name: str = "artifact", platform: str = "auto") -> dict[str, object]:
    raw = _bytes(data)
    label = _string(name, cap=4096, empty=False)
    assert label is not None
    if raw.startswith(PFF_MAGIC):
        return inspect_pff(raw, label)
    if raw.startswith(CFB_MAGIC):
        return analyze_msg(raw, label)
    if raw.startswith(b"From "):
        return analyze_mbox(raw, label)
    if raw.startswith(b"PK\x03\x04") or raw.lstrip().startswith((b"{", b"[")):
        return parse_chat_export(raw, platform=platform, name=label)
    raise MailDepthError("unsupported mail/chat archive format")


@_contract
def analyze_path(path: str | Path, *, platform: str = "auto",
                 pypff_module: object | None = None) -> dict[str, object]:
    source = Path(path)
    try:
        with source.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
    except OSError as exc:
        raise MailDepthError("input path could not be read") from exc
    if len(raw) > MAX_INPUT:
        raise MailDepthError("input exceeds size cap")
    if raw.startswith(PFF_MAGIC):
        return analyze_pff_path(source, pypff_module=pypff_module)
    return analyze_bytes(raw, name=source.name, platform=platform)


def _json_safe(value: object, *, include_bytes: bool = False) -> object:
    if isinstance(value, bytes):
        result: dict[str, object] = {"size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        if include_bytes:
            result["base64"] = base64.b64encode(value).decode("ascii")
        return result
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key in result:
                raise MailDepthError("render_json mapping keys collide after stringification")
            result[text_key] = _json_safe(item, include_bytes=include_bytes)
        return result
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, include_bytes=include_bytes) for item in value]
    return value


@_contract
def render_json(value: object, *, include_bytes: bool = False, pretty: bool = False) -> str:
    return json.dumps(_json_safe(value, include_bytes=include_bytes), sort_keys=True,
                      indent=2 if pretty else None, ensure_ascii=False, allow_nan=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="maildepth_archives.py",
                                     description="Offline PST/OST, MSG/mbox, and chat-export analyzer")
    parser.add_argument("inputs", nargs="+", help="mail/archive files to analyze read-only")
    parser.add_argument("--platform", choices=("auto", "slack", "discord", "teams"), default="auto")
    parser.add_argument("--json", action="store_true", help="emit JSON (the default; accepted for tooling)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    parser.add_argument("--include-bytes", action="store_true", help="include attachment bytes as base64")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        results = [{"input": str(path), "result": analyze_path(path, platform=args.platform)}
                   for path in args.inputs]
        output: object = results[0] if len(results) == 1 else results
        print(render_json(output, include_bytes=args.include_bytes, pretty=args.pretty))
        return 0
    except MailDepthError as exc:
        print(f"maildepth_archives: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "MailDepthError", "inspect_pff", "extract_pff_store", "analyze_pff_path",
    "analyze_msg", "analyze_mbox", "parse_slack_export", "parse_discord_export",
    "parse_teams_export", "parse_chat_export", "analyze_bytes", "analyze_path",
    "render_json", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
