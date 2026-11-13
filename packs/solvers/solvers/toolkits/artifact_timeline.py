"""Checked, offline host-artifact timelines and cross-source correlation.

The repository already has format-aware EVTX/export, registry-hive, SQLite browser, and
journald readers.  This module composes those readers without invoking programs, mounting an
image, or opening a network connection.  Each public decoder accepts supplied bytes and returns
an empty tuple unless the underlying format check succeeds and a trustworthy timestamp exists.

Correlations are deliberately conservative: events must come from distinct sources, fall in a
bounded time window, and share an exact normalized path/URL (or an explicit path embedded in a
registry value or shell command).  Mere temporal proximity and basename-only matches are never
enough.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

try:  # tests put solvers/toolkits directly on sys.path
    import nix_host as _nix
    import sqlite_artifacts as _sqlite
    import timeline as _timeline
    import windows as _windows
except ImportError:  # package-style import
    from . import nix_host as _nix
    from . import sqlite_artifacts as _sqlite
    from . import timeline as _timeline
    from . import windows as _windows


MAX_ARTIFACT = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EVENTS = 500_000
MAX_FILES = 512
MAX_TEXT = 32 * 1024
MAX_METADATA = 128
MAX_CORRELATION_EVENTS = 100_000
MAX_LINKS = 250_000
MAX_COMPARISONS = 1_000_000
MAX_REGISTRY_KEYS = 200_000
MAX_SHELLBAG_EVENTS = 5_000
UTC = dt.timezone.utc


@dataclass(frozen=True)
class ArtifactCorrelation:
    """A checked relationship between two events from distinct artifact sources."""

    kind: str
    entity: str
    start: dt.datetime
    end: dt.datetime
    events: tuple[_timeline.TimelineEvent, _timeline.TimelineEvent]
    sources: tuple[str, str]
    confidence: float
    rationale: str


def _blob(data: object) -> bytes | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    return raw if 0 < len(raw) <= MAX_ARTIFACT else None


def _text(value: object, cap: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    elif isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value)
    return str(value).replace("\x00", "")[:cap]


def _stamp(value: object) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    # windows.Stamp exposes exact FILETIME conversion through .dt.
    exact = getattr(value, "dt", None)
    if isinstance(exact, dt.datetime):
        return exact.replace(tzinfo=UTC) if exact.tzinfo is None else exact.astimezone(UTC)
    return _timeline.parse_timestamp(value)


def _metadata(values: Mapping | None) -> dict:
    if not isinstance(values, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, value in values.items():
        if len(out) >= MAX_METADATA:
            break
        rendered = _text(value, 4096)
        if rendered:
            out[_text(key, 128)] = rendered
    return out


def _bounded_text(value: object, cap: int) -> str | None:
    """Render text without silently turning two distinct oversized values into one."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            rendered = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        try:
            rendered = str(value)
        except Exception:
            return None
    if "\x00" in rendered:
        return None
    return rendered if len(rendered) <= cap else None


def _event_path(data: Mapping) -> str | None:
    wanted = (
        "Image", "NewProcessName", "ProcessName", "TargetFilename", "TargetObject",
        "ObjectName", "Path", "FileName", "Destination", "QueryName",
    )
    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in wanted:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return _bounded_text(value, 8192)
    return ""


def event_log_timeline(data: bytes, *, source: str = "event-log",
                       include_slack: bool = False) -> tuple[_timeline.TimelineEvent, ...]:
    """Normalize a complete EVTX/XML/JSON/CSV event-log artifact.

    EVTX slack is excluded by default because it is recovered evidence.  When explicitly asked
    for, it is marked in metadata and still requires a valid event timestamp.
    """

    raw = _blob(data)
    if (raw is None or not isinstance(source, str) or not source or len(source) > 4096
            or not isinstance(include_slack, bool)):
        return ()
    try:
        artifact = _windows.read(source, raw)
    except Exception:
        return ()
    if artifact is None or artifact.kind not in _windows.EVENT_KINDS or not artifact.complete:
        return ()
    records = list(artifact.events)
    if include_slack:
        records.extend(artifact.slack)
    if not records or len(records) > MAX_EVENTS:
        return ()
    out: list[_timeline.TimelineEvent] = []
    for record in records:
        if not isinstance(record, Mapping) or not isinstance(record.get("id"), int):
            return ()
        when = _stamp(record.get("time"))
        if when is None:
            continue
        action = _windows.event_name(record) or f"event_{record['id']}"
        fields = record.get("data") if isinstance(record.get("data"), Mapping) else {}
        meta = _metadata(fields)
        for key in ("id", "provider", "channel", "computer", "record", "sid", "pid"):
            if record.get(key) is not None:
                meta[key] = _text(record[key], 1024)
        recovered = bool(record.get("slack"))
        if recovered:
            meta["recovered"] = "evtx_slack"
        description = _text(record.get("message"), MAX_TEXT)
        path = _event_path(fields)
        if path is None:
            return ()
        out.append(_timeline.TimelineEvent(when, source, action, path, description, "event", meta))
    return tuple(sorted(out, key=_event_sort))


_REGISTRY_INTEREST = re.compile(
    r"(?:^|\\)(?:run(?:once|services|servicesonce)?|services|winlogon|"
    r"image file execution options|silentprocessexit|taskcache|bam|userassist|bagmru)(?:\\|$)",
    re.IGNORECASE,
)
_REGISTRY_PERSISTENCE = re.compile(
    r"(?:^|\\)(?:run(?:once|services|servicesonce)?|services|winlogon|"
    r"image file execution options|silentprocessexit|taskcache)(?:\\|$)",
    re.IGNORECASE,
)


def _registry_events(view: object, source: str, include_all: bool) -> tuple[_timeline.TimelineEvent, ...]:
    root = getattr(view, "root", None)
    walk = getattr(view, "walk", None)
    if root is None or not callable(walk):
        return ()
    try:
        walked = list(walk(limit=MAX_REGISTRY_KEYS + 1))
    except TypeError:  # a compatible checked view may expose only the default signature
        try:
            walked = list(walk())
        except Exception:
            return ()
    except Exception:
        return ()
    if len(walked) > MAX_REGISTRY_KEYS:
        return ()
    keys = [root, *walked]
    out: list[_timeline.TimelineEvent] = []
    seen: set[int] = set()
    for key in keys:
        if id(key) in seen:
            continue
        seen.add(id(key))
        path = _bounded_text(getattr(key, "path", ""), 8192)
        when = _stamp(getattr(key, "ts", None))
        if path is None:
            return ()
        if not path or when is None or (not include_all and not _REGISTRY_INTEREST.search(path)):
            continue
        try:
            values = key.values()
        except Exception:
            continue
        rendered = {}
        if isinstance(values, Mapping):
            for name, value in list(values.items())[:MAX_METADATA]:
                item = getattr(value, "data", None)
                if item not in (None, b"", "", []):
                    rendered[_text(name, 128) or "(Default)"] = _text(item, 4096)
        action = "registry_persistence" if _REGISTRY_PERSISTENCE.search(path) else "registry_key_write"
        out.append(_timeline.TimelineEvent(
            when, source, action, path, "; ".join(f"{k}={v}" for k, v in rendered.items()),
            "registry_last_write", {"values": rendered, "hive_kind": _text(getattr(view, "kind", ""), 64)},
        ))
    return tuple(sorted(out, key=_event_sort))


def registry_timeline(data: bytes, *, source: str = "registry",
                      include_all: bool = False) -> tuple[_timeline.TimelineEvent, ...]:
    """Return timestamped keys from a checked binary registry hive.

    ``.reg`` text exports intentionally decline: they carry values but no trustworthy key
    timestamps.  By default only persistence and user-activity key families are emitted.
    """

    raw = _blob(data)
    if (raw is None or not isinstance(source, str) or not source or len(source) > 4096
            or not isinstance(include_all, bool)):
        return ()
    try:
        view = _windows.Hive(raw)
    except Exception:
        return ()
    return _registry_events(view, source, include_all)


def _shellbag_events(view: object, source: str) -> tuple[_timeline.TimelineEvent, ...]:
    """Decode BagMRU paths from an already checked registry view."""

    find = getattr(view, "find", None)
    if not callable(find):
        return ()
    out: list[_timeline.TimelineEvent] = []
    total = 0

    def visit(key: object, prefix: str, depth: int) -> bool:
        nonlocal total
        if depth > 32 or total >= MAX_SHELLBAG_EVENTS:
            return False
        try:
            children = {child.name: child for child in key.subkeys()}
            values = key.values()
        except Exception:
            return False
        for name, value in values.items():
            if not str(name).isdigit() or not isinstance(getattr(value, "raw", None), bytes):
                continue
            component = _windows._shell_item_name(value.raw)
            if not component:
                continue
            if total >= MAX_SHELLBAG_EVENTS:
                return False
            path = f"{prefix}\\{component}" if prefix else component
            if len(path) > 8192:
                return False
            when = _stamp(getattr(key, "ts", None))
            if when is not None:
                out.append(_timeline.TimelineEvent(
                    when, source, "shellbag_folder_observed", path, "",
                    "registry_last_write", {"bagmru_value": str(name)},
                ))
                total += 1
            child = children.get(str(name))
            if child is not None and not visit(child, path, depth + 1):
                return False
        return True

    roots = (
        "Microsoft\\Windows\\Shell\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    )
    try:
        found = []
        for relative in roots:
            found.extend(find(relative))
    except Exception:
        return ()
    if not found:
        return ()
    for root in found:
        if not visit(root, "", 0):
            return ()
    return tuple(sorted(out, key=_event_sort))


def shellbag_timeline(data: bytes, *, source: str = "shellbags") -> tuple[_timeline.TimelineEvent, ...]:
    """Return timestamped folder observations from a checked USRCLASS/NTUSER hive."""

    raw = _blob(data)
    if raw is None or not isinstance(source, str) or not source or len(source) > 4096:
        return ()
    try:
        view = _windows.Hive(raw)
    except Exception:
        return ()
    return _shellbag_events(view, source)


def browser_timeline(data: bytes, *, source: str = "browser", wal: bytes | None = None,
                     journal: bytes | None = None) -> tuple[_timeline.TimelineEvent, ...]:
    """Normalize a recognized browser-history SQLite database and supplied sidecars."""

    raw = _blob(data)
    if raw is None or not isinstance(source, str) or not source or len(source) > 4096:
        return ()
    side_wal = None if wal is None else _blob(wal)
    side_journal = None if journal is None else _blob(journal)
    if (wal is not None and (side_wal is None or not _valid_wal(side_wal))) or (
        journal is not None and (side_journal is None or not _valid_journal(side_journal))
    ):
        return ()
    try:
        database = _sqlite.Database(raw, side_wal, side_journal, name=source, carve=True)
        kind = _sqlite.schema_kind(database)
        if kind not in {"chromium_history", "firefox_places", "safari_history"}:
            return ()
        records = _sqlite.records(database, art=source)
    except Exception:
        return ()
    if not records or len(records) > MAX_EVENTS:
        return ()
    out: list[_timeline.TimelineEvent] = []
    for record in records:
        if not isinstance(record, Mapping):
            return ()
        fields = record.get("f") if isinstance(record.get("f"), Mapping) else {}
        times = record.get("t") if isinstance(record.get("t"), Mapping) else {}
        for label, pair in times.items():
            when = None
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                when = _stamp(pair[1])
            else:
                when = _stamp(pair)
            if when is None:
                continue
            path = _bounded_text(fields.get("path") or fields.get("url") or fields.get("term"), 8192)
            if path is None:
                return ()
            if not path and isinstance(fields.get("url_chain"), list) and fields["url_chain"]:
                path = _bounded_text(fields["url_chain"][-1], 8192)
                if path is None:
                    return ()
            src = _text(record.get("src"), 512) or "live"
            meta = _metadata(fields)
            meta.update({"record_source": src, "table": _text(record.get("table"), 256),
                         "schema": kind, "timestamp_field": _text(label, 64)})
            out.append(_timeline.TimelineEvent(
                when, source, f"browser_{_text(record.get('kind'), 64)}", path,
                _text(fields.get("title"), 4096), "event", meta,
            ))
    return tuple(sorted(out, key=_event_sort))


def _valid_wal(data: bytes) -> bool:
    """Structural admission check for a supplied SQLite WAL sidecar."""

    if len(data) < 32:
        return False
    magic = int.from_bytes(data[:4], "big")
    page_size = int.from_bytes(data[8:12], "big")
    if magic not in (0x377F0682, 0x377F0683):
        return False
    if page_size == 1:
        page_size = 65_536
    if not (512 <= page_size <= 65_536) or page_size & (page_size - 1):
        return False
    frame_size = 24 + page_size
    if (len(data) - 32) % frame_size:
        return False
    salt = data[16:24]
    for offset in range(32, len(data), frame_size):
        if int.from_bytes(data[offset:offset + 4], "big") == 0 or data[offset + 8:offset + 16] != salt:
            return False
    return True


def _valid_journal(data: bytes) -> bool:
    """Structural admission check for an active SQLite rollback-journal sidecar."""

    if len(data) < 512 or data[:8] != b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
        return False
    sector = int.from_bytes(data[20:24], "big")
    page_size = int.from_bytes(data[24:28], "big")
    return sector >= 512 and sector & (sector - 1) == 0 and 512 <= page_size <= 65_536 \
        and page_size & (page_size - 1) == 0 and len(data) >= sector \
        and (len(data) - sector) % (page_size + 8) == 0


def _json_pairs(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_decoder() -> json.JSONDecoder:
    return json.JSONDecoder(object_pairs_hook=_json_pairs, parse_constant=_json_constant)


def _strict_json_objects(raw: bytes) -> list[dict] | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    stripped = text.strip()
    if not stripped:
        return None
    decoder = _json_decoder()
    if stripped.startswith("["):
        rows: list[dict] = []
        position = 1
        while True:
            while position < len(stripped) and stripped[position].isspace():
                position += 1
            if position >= len(stripped):
                return None
            if stripped[position] == "]":
                position += 1
                return rows if rows and not stripped[position:].strip() else None
            if len(rows) >= MAX_EVENTS:
                return None
            try:
                value, position = decoder.raw_decode(stripped, position)
            except (ValueError, RecursionError):
                return None
            if not isinstance(value, dict):
                return None
            rows.append(value)
            while position < len(stripped) and stripped[position].isspace():
                position += 1
            if position >= len(stripped):
                return None
            if stripped[position] == ",":
                position += 1
                while position < len(stripped) and stripped[position].isspace():
                    position += 1
                if position >= len(stripped) or stripped[position] == "]":
                    return None
                continue
            if stripped[position] != "]":
                return None
        return None
    try:
        doc, end = decoder.raw_decode(stripped)
        if stripped[end:].strip():
            raise json.JSONDecodeError("trailing data", stripped, end)
    except json.JSONDecodeError:
        rows = []
        for line in stripped.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if len(rows) >= MAX_EVENTS:
                return None
            try:
                value, end = decoder.raw_decode(candidate)
            except (ValueError, RecursionError):
                return None
            if not isinstance(value, dict) or candidate[end:].strip():
                return None
            rows.append(value)
        return rows or None
    except (ValueError, RecursionError):
        return None
    if isinstance(doc, dict):
        return [doc]
    return None


def journal_timeline(data: bytes, *, source: str = "journal") -> tuple[_timeline.TimelineEvent, ...]:
    """Normalize complete ``journalctl -o json``/JSONL supplied bytes.

    Binary journal files require external libsystemd tooling and therefore decline here; a
    sandbox runner can supply its JSON export to this pure-Python decoder.
    """

    raw = _blob(data)
    if raw is None or not isinstance(source, str) or not source or len(source) > 4096:
        return ()
    objects = _strict_json_objects(raw)
    if objects is None or len(objects) > MAX_EVENTS:
        return ()
    # Re-serialize after strict validation so the existing reader sees one object per line.
    text = "\n".join(json.dumps(item, ensure_ascii=False) for item in objects)
    try:
        records = _nix.nh.parse_journal_json(text)
    except Exception:
        return ()
    if len(records) != len(objects) or any(_stamp(record.get("time")) is None for record in records):
        return ()
    out: list[_timeline.TimelineEvent] = []
    for record in records:
        when = _stamp(record.get("time"))
        if when is None:  # guarded above; keeps the type checker honest
            return ()
        fields = record.get("fields") if isinstance(record.get("fields"), Mapping) else {}
        path = _bounded_text(fields.get("_EXE") or fields.get("CODE_FILE") or fields.get("OBJECT_PATH"), 8192)
        if path is None:
            return ()
        app = _text(record.get("app"), 512)
        meta = _metadata(fields)
        if record.get("pid") is not None:
            meta["pid"] = _text(record["pid"], 64)
        out.append(_timeline.TimelineEvent(
            when, source, f"journal_{app}" if app else "journal_message", path,
            _text(record.get("msg"), MAX_TEXT), "event", meta,
        ))
    return tuple(sorted(out, key=_event_sort))


_ZSH_HISTORY = re.compile(r"^: (\d{9,10}):(\d+);(.*)$")
_BASH_STAMP = re.compile(r"^#(\d{9,10})$")


def shell_history_timeline(data: bytes, *, source: str = "shell-history") -> tuple[_timeline.TimelineEvent, ...]:
    """Return only explicitly timestamped bash/zsh history entries.

    Untimestamped history has no defensible timeline position and therefore produces no event.
    Invalid UTF-8, NULs, dangling bash timestamp markers, or impossible epochs decline wholly.
    """

    raw = _blob(data)
    if raw is None or not isinstance(source, str) or not source or len(source) > 4096:
        return ()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    if "\x00" in text or len(text.splitlines()) > MAX_EVENTS * 2:
        return ()
    rows: list[tuple[int, str, int]] = []
    pending: tuple[int, int] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        zsh = _ZSH_HISTORY.fullmatch(line)
        if zsh:
            if pending is not None:
                return ()
            rows.append((int(zsh.group(1)), zsh.group(3), number))
            continue
        marker = _BASH_STAMP.fullmatch(line)
        if marker:
            if pending is not None:
                return ()
            pending = (int(marker.group(1)), number)
            continue
        if pending is not None:
            if not line:
                return ()
            rows.append((pending[0], line, pending[1]))
            pending = None
    if pending is not None or not rows:
        return ()
    out: list[_timeline.TimelineEvent] = []
    for epoch, command, number in rows:
        when = _timeline.parse_timestamp(epoch, "unix")
        if when is None or not command.strip():
            return ()
        out.append(_timeline.TimelineEvent(
            when, source, "shell_command", "", command[:MAX_TEXT], "event", {"line": number},
        ))
    return tuple(sorted(out, key=_event_sort))


def build_artifact_timeline(files: Mapping[str, bytes]) -> tuple[_timeline.TimelineEvent, ...]:
    """Auto-check supplied artifacts and build a deduplicated host timeline.

    Recognition is content driven.  Unrecognized or corrupt entries are ignored; no decoder is
    selected solely from a filename.
    """

    if not isinstance(files, Mapping) or not files or len(files) > MAX_FILES:
        return ()
    total = 0
    out: list[_timeline.TimelineEvent] = []
    for name, value in files.items():
        if not isinstance(name, str) or not name or not isinstance(value, (bytes, bytearray, memoryview)):
            return ()
        raw = bytes(value)
        total += len(raw)
        if not raw or len(raw) > MAX_ARTIFACT or total > MAX_TOTAL_BYTES:
            return ()
        parsed: Sequence[_timeline.TimelineEvent] = event_log_timeline(raw, source=name)
        if not parsed:
            reg = registry_timeline(raw, source=name)
            bags = shellbag_timeline(raw, source=name)
            parsed = tuple(reg) + tuple(bags)
        if not parsed:
            parsed = browser_timeline(raw, source=name)
        if not parsed:
            parsed = journal_timeline(raw, source=name)
        if not parsed:
            parsed = shell_history_timeline(raw, source=name)
        out.extend(parsed)
        if len(out) > MAX_EVENTS:
            return ()
    unique = {
        (event.timestamp, event.source, event.action, event.path, event.description): event
        for event in out
    }
    return tuple(sorted(unique.values(), key=_event_sort))


_QUOTED_WIN_PATH = re.compile(r"(?i)(?:\"((?:[a-z]:\\|\\\\)[^\"\r\n]+)\"|'((?:[a-z]:\\|\\\\)[^'\r\n]+)')")
_WIN_PATH = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\x00\r\n\t ;|<>\"']{3,}")
_POSIX_PATH = re.compile(r"(?<![:A-Za-z0-9])/(?:[^\s;|<>\"']+/)*[^\s;|<>\"']+")
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")


def _normalize_entity(value: str) -> str | None:
    text = value.strip().strip("'\"()[]{}.,")
    if not text or len(text) > 8192:
        return None
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", text):
        # URL paths and queries are case-sensitive; preserve the supplied spelling exactly.
        return "url:" + text
    if re.match(r"(?i)^[a-z]:\\", text) or text.startswith("\\\\"):
        converted = text.replace("/", "\\")
        if converted.startswith("\\\\"):
            converted = "\\\\" + re.sub(r"\\+", r"\\", converted[2:])
        else:
            converted = re.sub(r"\\+", r"\\", converted)
        return "path:" + converted.lower().rstrip("\\")
    if text.startswith("/"):
        return "path:" + re.sub(r"/+", "/", text).rstrip("/")
    return None


def _entities(event: _timeline.TimelineEvent) -> frozenset[str]:
    found: set[str] = set()
    direct = _normalize_entity(event.path)
    if direct:
        found.add(direct)
    values = [event.description] if len(event.description) < MAX_TEXT else []
    for key, value in event.metadata.items():
        if str(key).lower() in {
            "values", "command", "commandline", "image", "newprocessname", "path", "url",
            "url_chain", "targetfilename", "exe", "_exe",
        }:
            rendered = _text(value, 16384)
            if len(rendered) < 16384:
                values.append(rendered)
    for value in values:
        for match in _QUOTED_WIN_PATH.finditer(value):
            entity = _normalize_entity(match.group(1) or match.group(2))
            if entity:
                found.add(entity)
        for pattern in (_URL, _WIN_PATH, _POSIX_PATH):
            for match in pattern.finditer(value):
                entity = _normalize_entity(match.group())
                if entity:
                    found.add(entity)
    return frozenset(found)


def _role(event: _timeline.TimelineEvent) -> str:
    action = event.action.lower()
    if action in {"browser_download", "download"}:
        return "download"
    if action == "registry_persistence":
        return "persistence"
    if action == "shellbag_folder_observed":
        return "shellbag"
    if action == "shell_command":
        return "command"
    if action in {"sysmon_process_creation", "process_creation", "process create",
                  "process_execute", "process execute", "execute"}:
        return "execute"
    if action in {"sysmon_network_connection", "network_connection", "network connect",
                  "sysmon_dns_query", "dns_query"}:
        return "network"
    return ""


_RULES: dict[tuple[str, str], tuple[str, float, str]] = {
    ("download", "execute"): ("download-execute", 0.98, "downloaded path later executed"),
    ("persistence", "execute"): ("persistence-execute", 0.96, "registry persistence target later executed"),
    ("command", "execute"): ("command-execute", 0.94, "timestamped shell command matches executed path"),
    ("execute", "network"): ("execute-network", 0.92, "executed image later appears in network telemetry"),
    ("shellbag", "execute"): ("shellbag-execute", 0.90, "observed shell path later executed"),
}


def correlate_artifacts(events: Iterable[_timeline.TimelineEvent], *,
                        window_seconds: int = 300) -> tuple[ArtifactCorrelation, ...]:
    """Link exact shared entities across independently sourced artifact events."""

    if type(window_seconds) is not int or not 1 <= window_seconds <= 86_400:
        return ()
    bounded: list[_timeline.TimelineEvent] = []
    try:
        iterator = iter(events)
        for event in iterator:
            if len(bounded) >= MAX_CORRELATION_EVENTS or not isinstance(event, _timeline.TimelineEvent):
                return ()
            if (not isinstance(event.timestamp, dt.datetime) or type(event.source) is not str
                    or type(event.action) is not str or type(event.path) is not str
                    or type(event.description) is not str or not isinstance(event.metadata, Mapping)
                    or not event.source
                    or len(event.path) > 8192 or len(event.description) > MAX_TEXT
                    or len(event.metadata) > MAX_METADATA):
                return ()
            bounded.append(event)
    except Exception:
        return ()
    if not bounded:
        return ()
    ordered = sorted(bounded, key=_event_sort)
    by_entity: dict[str, list[tuple[_timeline.TimelineEvent, str]]] = {}
    memberships = 0
    for event in ordered:
        role = _role(event)
        if not role:
            continue
        try:
            entities = _entities(event)
        except Exception:
            return ()
        for entity in entities:
            memberships += 1
            if memberships > MAX_LINKS:
                return ()
            by_entity.setdefault(entity, []).append((event, role))
    limit = dt.timedelta(seconds=window_seconds)
    links: list[ArtifactCorrelation] = []
    seen: set[tuple] = set()
    comparisons = 0
    for entity, members in by_entity.items():
        members.sort(key=lambda item: _event_sort(item[0]))
        for left_index, (left, left_role) in enumerate(members):
            for right, right_role in members[left_index + 1:]:
                comparisons += 1
                if comparisons > MAX_COMPARISONS:
                    return ()
                delta = right.timestamp - left.timestamp
                if delta > limit:
                    break
                if delta <= dt.timedelta(0):
                    continue
                if left.source == right.source:
                    continue
                rule = _RULES.get((left_role, right_role))
                if rule is None:
                    continue
                identity = (rule[0], entity, left.timestamp, right.timestamp, left.source, right.source)
                if identity in seen:
                    continue
                seen.add(identity)
                sources = (left.source, right.source)
                links.append(ArtifactCorrelation(
                    rule[0], entity, left.timestamp, right.timestamp, (left, right), sources,
                    rule[1], rule[2],
                ))
                if len(links) > MAX_LINKS:
                    return ()
    return tuple(sorted(links, key=lambda link: (link.start, link.end, link.kind, link.entity)))


def _event_sort(event: _timeline.TimelineEvent) -> tuple:
    return (event.timestamp, event.source, event.action, event.path, event.description)


__all__ = [
    "ArtifactCorrelation", "event_log_timeline", "registry_timeline", "shellbag_timeline",
    "browser_timeline", "journal_timeline", "shell_history_timeline",
    "build_artifact_timeline", "correlate_artifacts",
]
