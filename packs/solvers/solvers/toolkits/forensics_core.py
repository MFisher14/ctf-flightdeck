"""Offline memory-forensics planning and checked super-timeline correlation.

This module never invokes Volatility, a shell, or an external process.  It only inventories
the locally installed Volatility 3 plugin *files* and produces immutable execution plans for
an analyst/sandbox runner.  Timeline inputs are supplied bytes and are accepted only when the
entire JSON/JSONL/CSV/bodyfile structure is valid and yields normalized timestamps.

The existing :mod:`timeline` normalizer remains the source of timestamp semantics.  This file
adds strict in-memory format admission, multi-artifact deduplication, and evidence correlation.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:  # tests place solvers/toolkits directly on sys.path
    import timeline as _timeline
except ImportError:  # package-style import
    from . import timeline as _timeline


MAX_ARTIFACT = 64 * 1024 * 1024
MAX_TOTAL_TIMELINE = 256 * 1024 * 1024
MAX_RECORDS = 500_000
MAX_CORRELATION_EVENTS = 100_000
MAX_ENTITY_LINKS = 1_000_000


@dataclass(frozen=True)
class PluginStep:
    plugin: str
    phase: str
    purpose: str
    depends_on: tuple[str, ...] = ()
    available: bool = False


@dataclass(frozen=True)
class VolatilityPlan:
    os_family: str
    goals: tuple[str, ...]
    steps: tuple[PluginStep, ...]
    unavailable: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class Correlation:
    kind: str
    entity: str
    start: dt.datetime
    end: dt.datetime
    events: tuple[_timeline.TimelineEvent, ...]
    sources: tuple[str, ...]
    confidence: float
    rationale: str


def installed_volatility_plugins() -> frozenset[str]:
    """Return installed plugin module names without importing or executing a plugin.

    Volatility 3 ships plugins under ``volatility3/framework/plugins``.  Reading that package's
    file tree is sufficient to cross-check plan spellings and avoids framework initialization.
    """

    try:
        import volatility3
    except Exception:
        return frozenset()
    root = Path(volatility3.__file__).resolve().parent / "framework" / "plugins"
    if not root.is_dir():
        return frozenset()
    found = set()
    for path in root.rglob("*.py"):
        if path.name == "__init__.py" or path.name.startswith("test_"):
            continue
        rel = path.relative_to(root).with_suffix("")
        found.add(".".join(rel.parts))
    return frozenset(found)


_BASE_PLUGINS: dict[str, tuple[tuple[str, str, str, tuple[str, ...]], ...]] = {
    "windows": (
        ("windows.info", "identify", "kernel/build and symbol sanity", ()),
        ("windows.pslist", "process", "linked process inventory", ("windows.info",)),
        ("windows.pstree", "process", "parent/child process relationships", ("windows.pslist",)),
        ("windows.psscan", "process", "pool-scanned hidden or terminated processes", ("windows.info",)),
        ("windows.cmdline", "process", "process command lines", ("windows.pslist",)),
        ("windows.envars", "process", "process environment variables", ("windows.pslist",)),
    ),
    "linux": (
        ("banners", "identify", "kernel banner and symbol selection", ()),
        ("linux.pslist", "process", "task-list process inventory", ("banners",)),
        ("linux.pstree", "process", "parent/child task relationships", ("linux.pslist",)),
        ("linux.psscan", "process", "scanned tasks outside the linked list", ("banners",)),
        ("linux.psaux", "process", "process command lines", ("linux.pslist",)),
        ("linux.envars", "process", "process environment variables", ("linux.pslist",)),
    ),
    "mac": (
        ("banners", "identify", "Darwin kernel banner and symbol selection", ()),
        ("mac.pslist", "process", "process inventory", ("banners",)),
        ("mac.pstree", "process", "parent/child process relationships", ("mac.pslist",)),
        ("mac.psaux", "process", "process arguments", ("mac.pslist",)),
    ),
}


_GOAL_PLUGINS: dict[str, dict[str, tuple[tuple[str, str, str, tuple[str, ...]], ...]]] = {
    "network": {
        "windows": (("windows.netscan", "network", "TCP/UDP endpoints and owning processes", ("windows.pslist",)),),
        "linux": (("linux.sockstat", "network", "socket endpoints and owning tasks", ("linux.pslist",)),),
        "mac": (("mac.netstat", "network", "network endpoints and owning processes", ("mac.pslist",)),),
    },
    "malware": {
        "windows": (
            ("windows.malware.malfind", "malware", "suspicious executable VADs", ("windows.pslist",)),
            ("windows.vadinfo", "malware", "virtual-memory region context", ("windows.pslist",)),
            ("windows.dlllist", "malware", "loaded module anomalies", ("windows.pslist",)),
            ("yarascan", "malware", "analyst-provided YARA triage", ()),
        ),
        "linux": (
            ("linux.malware.malfind", "malware", "suspicious executable VMAs", ("linux.pslist",)),
            ("linux.malware.check_creds", "malware", "shared credential-structure anomalies", ("linux.pslist",)),
            ("yarascan", "malware", "analyst-provided YARA triage", ()),
        ),
        "mac": (
            ("mac.malfind", "malware", "suspicious executable mappings", ("mac.pslist",)),
            ("yarascan", "malware", "analyst-provided YARA triage", ()),
        ),
    },
    "files": {
        "windows": (
            ("windows.filescan", "files", "pool-scanned file objects", ("windows.info",)),
            ("windows.dumpfiles", "files", "candidate file reconstruction plan", ("windows.filescan",)),
        ),
        "linux": (("linux.lsof", "files", "open files by task", ("linux.pslist",)),),
        "mac": (("mac.lsof", "files", "open files by process", ("mac.pslist",)),),
    },
    "credentials": {
        "windows": (
            ("windows.hashdump", "credentials", "cached account hashes when registry layers exist", ("windows.info",)),
            ("windows.lsadump", "credentials", "LSA secrets when registry layers exist", ("windows.info",)),
            ("windows.getsids", "credentials", "process token SID context", ("windows.pslist",)),
        ),
        "linux": (("linux.check_creds", "credentials", "credential structure sharing", ("linux.pslist",)),),
        "mac": (("mac.check_syscall", "credentials", "kernel syscall integrity context", ("banners",)),),
    },
    "shell": {
        "windows": (
            ("windows.consoles", "shell", "console command history", ("windows.pslist",)),
            ("windows.cmdscan", "shell", "legacy command history structures", ("windows.pslist",)),
        ),
        "linux": (("linux.bash", "shell", "bash history structures", ("linux.pslist",)),),
        "mac": (("mac.bash", "shell", "bash history structures", ("mac.pslist",)),),
    },
    "persistence": {
        "windows": (
            ("windows.registry.hivelist", "persistence", "registry hive inventory", ("windows.info",)),
            ("windows.registry.userassist", "persistence", "interactive execution evidence", ("windows.registry.hivelist",)),
            ("windows.svcscan", "persistence", "service configuration", ("windows.pslist",)),
            ("windows.scheduled_tasks", "persistence", "scheduled task definitions", ("windows.registry.hivelist",)),
        ),
        "linux": (("linux.keyboard_notifiers", "persistence", "keyboard notifier hooks", ("banners",)),),
        "mac": (("mac.kauth_scopes", "persistence", "KAUTH listener integrity", ("banners",)),),
    },
}


def build_volatility_plan(os_family: str, goals: Sequence[str] = ("network", "malware", "files", "shell", "persistence")) -> VolatilityPlan | None:
    """Build a dependency-ordered, non-executable Volatility 3 plan.

    Unknown operating systems or goals decline with ``None``.  Missing local plugins remain in
    the plan with ``available=False`` so an analyst can distinguish coverage intent from the
    capabilities of this installation.
    """

    if not isinstance(os_family, str) or not isinstance(goals, Sequence) or isinstance(goals, (str, bytes)) or len(goals) > 32:
        return None
    os_name = os_family.strip().lower()
    if os_name not in _BASE_PLUGINS:
        return None
    selected = tuple(dict.fromkeys(str(goal).strip().lower() for goal in goals))
    if any(goal not in _GOAL_PLUGINS for goal in selected):
        return None
    inventory = installed_volatility_plugins()
    definitions = list(_BASE_PLUGINS[os_name])
    for goal in selected:
        definitions.extend(_GOAL_PLUGINS[goal][os_name])
    ordered: list[PluginStep] = []
    seen = set()
    for plugin, phase, purpose, dependencies in definitions:
        if plugin in seen:
            continue
        seen.add(plugin)
        ordered.append(PluginStep(plugin, phase, purpose, dependencies, plugin in inventory))
    unavailable = tuple(step.plugin for step in ordered if not step.available)
    notes = (
        "declarative plan only; no plugin invocation is performed",
        "run an image only in the repository Docker sandbox and supply symbols offline",
        "dump/extraction plugins require a separate explicit analyst action",
    )
    return VolatilityPlan(os_name, selected, tuple(ordered), unavailable, notes)


def _strict_json_records(text: str) -> list[Mapping] | None:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(item, Mapping):
                return None
            records.append(item)
        return records or None
    if isinstance(obj, list):
        return list(obj) if obj and all(isinstance(item, Mapping) for item in obj) else None
    if isinstance(obj, Mapping):
        for key in ("events", "records", "rows", "artifacts", "data"):
            value = obj.get(key)
            if isinstance(value, list):
                return list(value) if isinstance(value, list) and value and all(isinstance(item, Mapping) for item in value) else None
        return [obj]
    return None


def _strict_csv(text: str) -> tuple[str, list[Mapping]] | None:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or len(lines) > MAX_RECORDS + 1:
        return None
    first = lines[0]
    if first.count("|") == 10 and not any(word in first.lower() for word in ("timestamp", "date", "time")):
        for line in lines:
            fields = line.split("|")
            if len(fields) != 11 or any(not re.fullmatch(r"-?\d+", fields[index].strip()) for index in (7, 8, 9, 10)):
                return None
        return "bodyfile", []
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return None
    if len(rows) < 2 or len(rows[0]) < 2 or len(set(rows[0])) != len(rows[0]):
        return None
    width = len(rows[0])
    if any(len(row) != width for row in rows[1:]):
        return None
    reader = csv.DictReader(io.StringIO(text))
    records = list(reader)
    return ("csv", records) if records else None


def decode_timeline_artifact(data: object, *, source: str = "artifact", format_hint: str | None = None) -> tuple[_timeline.TimelineEvent, ...]:
    """Strictly decode one supplied JSON/JSONL/CSV/bodyfile timeline export.

    Binary data, replacement-character decoding, partially malformed JSONL/CSV, and exports
    without any recognized timestamp all decline as an empty tuple.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_ARTIFACT or b"\x00" in raw[:4096]:
        return ()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ()
    hint = (format_hint or "").strip().lower()
    events: list[_timeline.TimelineEvent]
    try:
        if hint in {"json", "jsonl", "ndjson"} or (not hint and text.lstrip().startswith(("{", "["))):
            records = _strict_json_records(text)
            if not records or len(records) > MAX_RECORDS:
                return ()
            events = _timeline.ingest_records(records, source_hint=source)
        elif hint in {"csv", "bodyfile", ""}:
            parsed = _strict_csv(text)
            if parsed is None:
                return ()
            kind, records = parsed
            events = (_timeline.parse_bodyfile(text, source=source) if kind == "bodyfile"
                      else _timeline.ingest_records(records, source_hint=source))
        else:
            return ()
    except (ValueError, TypeError, csv.Error):
        return ()
    return tuple(events) if events else ()


def build_super_timeline(artifacts: Mapping[str, bytes]) -> tuple[_timeline.TimelineEvent, ...]:
    """Normalize supplied exports, merge them, and deduplicate identical evidence rows."""

    if not isinstance(artifacts, Mapping) or len(artifacts) > 10_000:
        return ()
    merged, seen, consumed = [], set(), 0
    for name, data in artifacts.items():
        if not isinstance(data, (bytes, bytearray, memoryview)):
            continue
        consumed += len(data)
        if consumed > MAX_TOTAL_TIMELINE:
            return ()
        for event in decode_timeline_artifact(data, source=str(name)[:512]):
            key = (event.timestamp, event.source, event.action, event.path, event.description,
                   json.dumps(event.metadata, sort_keys=True, default=str, separators=(",", ":")))
            if key not in seen:
                seen.add(key)
                merged.append(event)
    merged.sort(key=lambda event: (event.timestamp, event.source, event.path, event.action))
    return tuple(merged)


_PATH_RE = re.compile(r"(?:[a-zA-Z]:[\\/]|/)[^\s\"'<>|]+")
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _event_text(event: _timeline.TimelineEvent) -> str:
    return " ".join((event.source, event.action, event.path, event.description,
                     json.dumps(event.metadata, sort_keys=True, default=str))).casefold()


def _categories(event: _timeline.TimelineEvent) -> frozenset[str]:
    text = _event_text(event)
    found = set()
    for category, words in {
        "download": ("download", "browser", "http", "url", "zone.identifier"),
        "file": ("file", "create", "write", "usn", "mft", "extract"),
        "execute": ("execute", "process", "prefetch", "amcache", "shimcache", "cmdline", "pslist"),
        "persistence": ("registry", "run key", "service", "scheduled", "startup", "autorun", "persistence"),
        "network": ("network", "connect", "netscan", "socket", "dns", "tcp", "udp"),
    }.items():
        if any(word in text for word in words):
            found.add(category)
    return frozenset(found)


def _entities(event: _timeline.TimelineEvent) -> frozenset[str]:
    text = " ".join((event.path, event.description, json.dumps(event.metadata, default=str)))
    entities = set()
    for path in _PATH_RE.findall(text):
        normalized = path.rstrip(".,;:)]}").replace("\\", "/").casefold()
        entities.add("path:" + normalized)
        basename = normalized.rsplit("/", 1)[-1]
        if len(basename) >= 3:
            entities.add("file:" + basename)
    for ip in _IP_RE.findall(text):
        try:
            if all(0 <= int(part) <= 255 for part in ip.split(".")):
                entities.add("ip:" + ip)
        except ValueError:
            pass
    metadata = event.metadata if isinstance(event.metadata, Mapping) else {}
    for key in ("pid", "process_id", "ppid", "user", "username", "sha1", "sha256", "md5", "host", "hostname"):
        value = metadata.get(key)
        if value not in (None, ""):
            entities.add(f"{key}:{str(value).casefold()}")
    return frozenset(entities)


def correlate_events(events: Iterable[_timeline.TimelineEvent], *, window_seconds: int = 600) -> tuple[Correlation, ...]:
    """Correlate checked timeline events into evidence-backed sequences.

    A result requires distinct sources, a shared concrete entity, chronological ordering, and
    one of three meaningful category sequences.  Mere temporal proximity never emits a result.
    """

    if not 1 <= window_seconds <= 86_400:
        return ()
    ordered = []
    for event in events:
        if isinstance(event, _timeline.TimelineEvent):
            ordered.append(event)
            if len(ordered) > MAX_CORRELATION_EVENTS:
                return ()
    ordered.sort(key=lambda event: event.timestamp)
    if len(ordered) < 2:
        return ()
    definitions = (
        ("download-execute", ("download", "execute"), "download evidence followed by execution"),
        ("persistence-execute", ("persistence", "execute"), "persistence creation followed by execution"),
        ("file-execute-network", ("file", "execute", "network"), "file arrival, execution, then network activity"),
    )
    features = [(event, _categories(event), _entities(event)) for event in ordered]
    by_entity: dict[str, list[tuple[_timeline.TimelineEvent, frozenset[str]]]] = {}
    links = 0
    for event, categories, entities in features:
        for entity in entities:
            by_entity.setdefault(entity, []).append((event, categories))
            links += 1
            if links > MAX_ENTITY_LINKS:
                return ()

    # One latest partial sequence per entity/rule is enough for triage and keeps runtime and
    # result volume linear.  Duplicate path:/file: views of the same events collapse below.
    candidates: dict[tuple, Correlation] = {}
    for entity, items in by_entity.items():
        for kind, sequence, rationale in definitions:
            states: list[tuple[_timeline.TimelineEvent, ...] | None] = [None] * len(sequence)
            for event, categories in items:
                snapshot = list(states)
                for stage in range(len(sequence) - 1, 0, -1):
                    previous = snapshot[stage - 1]
                    if previous is None or sequence[stage] not in categories:
                        continue
                    elapsed = (event.timestamp - previous[0].timestamp).total_seconds()
                    if 0 <= elapsed <= window_seconds and event is not previous[-1]:
                        states[stage] = previous + (event,)
                        if stage != len(sequence) - 1:
                            continue
                        chosen = states[stage]
                        sources = tuple(sorted({item.source for item in chosen}))
                        if len(sources) < 2:
                            continue
                        evidence_key = (kind, tuple((item.timestamp, item.source, item.action, item.path) for item in chosen))
                        confidence = min(0.99, 0.78 + 0.06 * len(chosen) + 0.03 * (len(sources) - 2))
                        candidate = Correlation(kind, entity, chosen[0].timestamp, chosen[-1].timestamp,
                                                chosen, sources, confidence, rationale)
                        prior = candidates.get(evidence_key)
                        preference = lambda value: (value.entity.startswith("file:"), -len(value.entity), value.entity)
                        if prior is None or preference(candidate) > preference(prior):
                            candidates[evidence_key] = candidate
                if sequence[0] in categories:
                    states[0] = (event,)
                for stage, state in enumerate(states):
                    if state is not None and (event.timestamp - state[0].timestamp).total_seconds() > window_seconds:
                        states[stage] = None
    return tuple(sorted(candidates.values(), key=lambda item: (item.start, item.kind, item.entity)))


__all__ = [
    "Correlation", "PluginStep", "VolatilityPlan", "build_super_timeline",
    "build_volatility_plan", "correlate_events", "decode_timeline_artifact",
    "installed_volatility_plugins",
]
