"""Offline memory-forensics depth for supplied Volatility results.

This module is deliberately an orchestrator and result analyzer, never an executor.  It
selects checked Windows/Linux/macOS symbol strategies from supplied metadata, builds richer
Volatility 3 plugin plans, strictly normalizes already-rendered JSON/JSONL/CSV output, and
correlates process, handle, injection, and credential evidence.  It never opens a memory image,
initializes Volatility, runs a plugin, invokes a subprocess, or contacts a symbol server.

The earlier :mod:`forensics_core` remains the generic planner/timeline layer.  This module
adds profile/version support and cross-plugin evidence checks without modifying or duplicating
that API.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


MAX_INPUT = 64 * 1024 * 1024
MAX_ROWS = 250_000
MAX_FIELDS = 512
MAX_FIELD_TEXT = 16_384
MAX_RECORDS_ANALYZED = 500_000
MAX_HEADER_TEXT = MAX_FIELDS * 260
MAX_JSON_DEPTH = 64


@dataclass(frozen=True)
class ProfileSelection:
    os_family: str
    version: str
    architecture: str
    image_format: str
    symbol_strategy: str
    symbol_hint: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class MemoryPlanStep:
    plugin: str
    phase: str
    purpose: str
    depends_on: tuple[str, ...] = ()
    arguments: tuple[tuple[str, str], ...] = ()
    available: bool = False
    sensitive: bool = False


@dataclass(frozen=True)
class MemoryDepthPlan:
    profile: ProfileSelection
    goals: tuple[str, ...]
    steps: tuple[MemoryPlanStep, ...]
    unavailable: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class MemoryRecord:
    plugin: str
    os_family: str
    kind: str
    pid: int | None
    ppid: int | None
    tid: int | None
    process: str
    address: int | None
    end: int | None
    path: str
    object_type: str
    protection: str
    access: int | None
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MemoryFinding:
    kind: str
    os_family: str
    pid: int | None
    process: str
    confidence: float
    evidence: tuple[str, ...]
    details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CredentialArtifact:
    kind: str
    account: str
    verifier: str
    source_plugin: str
    evidence: str


def installed_plugin_modules() -> frozenset[str]:
    """Inventory Volatility plugin module files without importing any plugin."""

    try:
        import volatility3
    except Exception:
        return frozenset()
    root = Path(volatility3.__file__).resolve().parent / "framework" / "plugins"
    if not root.is_dir():
        return frozenset()
    found: set[str] = set()
    try:
        paths = root.rglob("*.py")
        for path in paths:
            if path.name == "__init__.py" or path.name.startswith("test_"):
                continue
            found.add(".".join(path.relative_to(root).with_suffix("").parts))
    except OSError:
        return frozenset()
    return frozenset(found)


_IMAGE_FORMATS = {
    "raw": "raw", "linear": "raw", "lime": "lime", "avml": "lime",
    "crashdump": "windows-crashdump", "windows-crashdump": "windows-crashdump",
    "hiberfil": "windows-hibernation", "hibernation": "windows-hibernation",
    "vmware": "vmware", "vmem": "vmware", "elf-core": "elf-core",
    "vmcore": "elf-core", "makedumpfile": "makedumpfile", "qemu": "qemu",
}
_ARCHES = {
    "amd64": "x64", "x86_64": "x64", "x64": "x64", "i386": "x86",
    "i686": "x86", "x86": "x86", "arm64": "arm64", "aarch64": "arm64",
}


def _clean_text(value: object, cap: int = MAX_FIELD_TEXT) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:cap]


def _metadata_map(metadata: object) -> dict[str, str] | None:
    if not isinstance(metadata, Mapping) or len(metadata) > 128:
        return None
    out = {}
    for key, value in metadata.items():
        name = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
        if not name or len(name) > 128 or name in out:
            return None
        if isinstance(value, (Mapping, list, tuple, set, bytes, bytearray, memoryview, bool)):
            return None
        text = _clean_text(value, 8193)
        if "\x00" in str(value) or len(text) > 8192:
            return None
        out[name] = text
    return out


def _architecture(meta: Mapping[str, str], banner: str = "") -> str | None:
    supplied = meta.get("architecture") or meta.get("arch") or meta.get("machine")
    if supplied:
        arch = _ARCHES.get(supplied.casefold())
        if arch:
            return arch
        return None
    lowered = banner.casefold()
    for marker, arch in _ARCHES.items():
        if marker in lowered:
            return arch
    return None


def _image_format(meta: Mapping[str, str]) -> str | None:
    supplied = (meta.get("image_format") or meta.get("format") or "raw").casefold()
    return _IMAGE_FORMATS.get(supplied)


def _windows_version(build: int) -> str:
    if build <= 2195:
        return "Windows 2000"
    if build <= 3790:
        return "Windows XP/Server 2003"
    if build <= 6002:
        return "Windows Vista/Server 2008"
    if build <= 7601:
        return "Windows 7/Server 2008 R2"
    if build <= 9200:
        return "Windows 8/Server 2012"
    if build <= 9600:
        return "Windows 8.1/Server 2012 R2"
    if build < 22000:
        return "Windows 10/Server 2016-2022"
    return "Windows 11/Server 2025+"


MAX_ISF_INDEX = 4096

ISF_MATCHED = "exact-banner ISF matched among the local symbol tables"
ISF_UNMATCHED = "no local ISF carries this banner: generate one offline from the matching vmlinux/System.map"


def _isf_index(index: object) -> dict[str, str] | None:
    """A checked {banner: ISF path} map, keyed by the banner as it is compared (no NUL, no line end).

    The caller reads the tables (``memory.linux_isfs``); this module still opens nothing.
    """

    if not isinstance(index, Mapping) or len(index) > MAX_ISF_INDEX:
        return None
    out: dict[str, str] = {}
    for banner, path in index.items():
        if not isinstance(banner, str) or isinstance(path, (bytes, bytearray, memoryview, bool)) or path is None:
            return None
        key, where = _clean_text(banner, 8193), _clean_text(path, 4097)
        if not key.startswith("Linux version ") or len(key) > 8192 or not where or len(where) > 4096:
            return None
        if out.setdefault(key, where) != where:
            return None
    return out


def select_profile(
    os_family: str,
    metadata: Mapping[str, object],
    isf_index: Mapping[str, object] | None = None,
) -> ProfileSelection | None:
    """Select an offline symbol/profile strategy from checked supplied metadata.

    Volatility 3 uses symbol tables rather than Volatility 2 profile names.  The returned hint
    is therefore descriptive and never triggers a download.

    ``isf_index`` (Linux, B-136) is a ``{banner: path}`` map of the Linux symbol tables that exist
    locally, as ``memory.linux_isfs`` reads them.  With it the selection says whether the image's
    exact banner has a table: ``symbol_strategy`` is ``ISF_MATCHED`` and ``symbol_hint`` the
    table's path when one was made for a banner the supplied banner starts with (Volatility's own
    test), else ``ISF_UNMATCHED`` with the name the missing table would take.  A table is never
    chosen by release alone, and an ``isf`` named in the metadata is the analyst's choice and is
    kept.  A malformed index yields ``None``, like malformed metadata.
    """

    if not isinstance(os_family, str):
        return None
    index = None
    if isf_index is not None:
        index = _isf_index(isf_index)
        if index is None:
            return None
    family = os_family.strip().casefold()
    if family == "darwin":
        family = "mac"
    if family not in {"windows", "linux", "mac"}:
        return None
    meta = _metadata_map(metadata)
    if meta is None:
        return None
    image_format = _image_format(meta)
    if image_format is None:
        return None
    compatible_formats = {
        "windows": {"raw", "windows-crashdump", "windows-hibernation", "vmware", "qemu"},
        "linux": {"raw", "lime", "vmware", "elf-core", "makedumpfile", "qemu"},
        "mac": {"raw", "vmware"},
    }
    if image_format not in compatible_formats[family]:
        return None
    banner = meta.get("banner") or meta.get("kernel_banner") or ""
    arch = _architecture(meta, banner)
    if arch is None:
        return None

    if family == "windows":
        build_text = meta.get("build") or meta.get("build_number") or meta.get("nt_build")
        if not build_text and banner:
            match = re.search(r"(?:build\s+|10\.0\.)(\d{4,6})", banner, re.I)
            build_text = match.group(1) if match else ""
        if not build_text or not re.fullmatch(r"\d{4,6}", build_text):
            return None
        build = int(build_text)
        if not 2195 <= build <= 99999:
            return None
        version = _windows_version(build)
        guid = (meta.get("pdb_guid") or meta.get("guid") or "").replace("-", "")
        age = meta.get("pdb_age") or meta.get("age") or ""
        if guid or age:
            if not re.fullmatch(r"[0-9a-fA-F]{32}", guid) or not re.fullmatch(r"\d{1,4}", age):
                return None
            hint = f"ntkrnlmp.pdb/{guid.upper()}{int(age):x}"
            evidence = (f"build={build}", f"pdb={guid.upper()}/{age}", f"arch={arch}")
        else:
            hint = f"windows-build-{build}-{arch}"
            evidence = (f"build={build}", f"arch={arch}")
        return ProfileSelection(family, version, arch, image_format,
                                "offline PDB/ISF cache with banner/PDB automagic", hint, evidence)

    if family == "linux":
        match = re.search(r"Linux version\s+([^\s]+)", banner)
        if not match or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+._A-Za-z0-9]*)", match.group(1)):
            return None
        version = match.group(1)
        isf = meta.get("isf") or meta.get("symbol_table") or ""
        if isf and not re.fullmatch(r"[A-Za-z0-9_.+/-]{1,512}", isf):
            return None
        hint = isf or f"linux-{version}-{arch}.json.xz"
        strategy = "exact-banner ISF generated offline from matching vmlinux/System.map"
        evidence = (f"banner={banner[:512]}", f"arch={arch}")
        if index is not None and not isf:
            # The longest table banner the image's banner starts with: an exact match, never a
            # release-only one (two builds of one release have different tables).
            made_for = max((key for key in index if banner.startswith(key)), key=len, default=None)
            if made_for is not None:
                strategy, hint = ISF_MATCHED, index[made_for]
                evidence += ("isf=matched",)
            else:
                strategy = ISF_UNMATCHED
                evidence += (f"isf=unmatched ({len(index)} local)",)
        return ProfileSelection(family, f"Linux {version}", arch, image_format,
                                strategy, hint, evidence)

    match = re.search(r"Darwin Kernel Version\s+([0-9]+(?:\.[0-9]+){1,2})", banner, re.I)
    if not match:
        return None
    version = match.group(1)
    isf = meta.get("isf") or meta.get("symbol_table") or ""
    if isf and not re.fullmatch(r"[A-Za-z0-9_.+/-]{1,512}", isf):
        return None
    hint = isf or f"darwin-{version}-{arch}.json.xz"
    return ProfileSelection(family, f"Darwin {version}", arch, image_format,
                            "exact-Darwin-build ISF generated offline from matching kernel/KDK",
                            hint, (f"banner={banner[:512]}", f"arch={arch}"))


_BASE_STEPS: dict[str, tuple[tuple[str, str, str, tuple[str, ...], bool], ...]] = {
    "windows": (
        ("windows.info", "identify", "kernel, layer and symbol sanity", (), False),
        ("windows.pslist", "process", "active process list", ("windows.info",), False),
        ("windows.psscan", "process", "pool-scanned processes", ("windows.info",), False),
        ("windows.malware.psxview", "process", "cross-view hidden-process comparison", ("windows.pslist", "windows.psscan"), False),
        ("windows.pstree", "process", "parent/child relationships", ("windows.pslist",), False),
        ("windows.cmdline", "process", "process command lines", ("windows.pslist",), False),
        ("windows.envars", "process", "process environments", ("windows.pslist",), False),
    ),
    "linux": (
        ("banners", "identify", "exact Linux banner and symbol-table match", (), False),
        ("linux.vmcoreinfo", "identify", "VMCOREINFO offsets when present", ("banners",), False),
        ("linux.pslist", "process", "task-list processes", ("banners",), False),
        ("linux.psscan", "process", "scanned task structures", ("banners",), False),
        ("linux.pidhashtable", "process", "PID hash-table cross-view", ("linux.pslist",), False),
        ("linux.pstree", "process", "parent/child task relationships", ("linux.pslist",), False),
        ("linux.psaux", "process", "process command lines", ("linux.pslist",), False),
        ("linux.envars", "process", "process environments", ("linux.pslist",), False),
    ),
    "mac": (
        ("banners", "identify", "exact Darwin banner and symbol-table match", (), False),
        ("mac.pslist", "process", "active process list", ("banners",), False),
        ("mac.pstree", "process", "parent/child relationships", ("mac.pslist",), False),
        ("mac.psaux", "process", "process arguments", ("mac.pslist",), False),
        ("mac.proc_maps", "process", "process memory maps", ("mac.pslist",), False),
    ),
}


_GOAL_STEPS: dict[str, dict[str, tuple[tuple[str, str, str, tuple[str, ...], bool], ...]]] = {
    "handles": {
        "windows": (
            ("windows.handles", "handles", "open handles, object targets and access masks", ("windows.pslist",), False),
            ("windows.joblinks", "handles", "job-object process relationships", ("windows.pslist",), False),
            ("windows.sessions", "handles", "session membership", ("windows.pslist",), False),
            ("windows.privileges", "handles", "token privileges", ("windows.pslist",), False),
        ),
        "linux": (
            ("linux.lsof", "handles", "open files by process", ("linux.pslist",), False),
            ("linux.capabilities", "handles", "process capabilities", ("linux.pslist",), False),
            ("linux.ptrace", "handles", "ptrace relationships", ("linux.pslist",), False),
        ),
        "mac": (
            ("mac.lsof", "handles", "open files by process", ("mac.pslist",), False),
            ("mac.list_files", "handles", "vnode/file-object inventory", ("mac.pslist",), False),
        ),
    },
    "injection": {
        "windows": (
            ("windows.malware.malfind", "injection", "private executable VAD candidates", ("windows.pslist",), False),
            ("windows.vadinfo", "injection", "VAD protection and backing context", ("windows.pslist",), False),
            ("windows.malware.ldrmodules", "injection", "PEB loader-list discrepancies", ("windows.pslist",), False),
            ("windows.malware.suspicious_threads", "injection", "thread starts outside expected modules", ("windows.pslist",), False),
            ("windows.malware.hollowprocesses", "injection", "process hollowing checks", ("windows.pslist",), False),
            ("windows.malware.processghosting", "injection", "ghosted process checks", ("windows.pslist",), False),
            ("windows.threads", "injection", "thread start addresses", ("windows.pslist",), False),
            ("windows.dlllist", "injection", "loaded module baseline", ("windows.pslist",), False),
        ),
        "linux": (
            ("linux.malware.malfind", "injection", "private executable VMA candidates", ("linux.pslist",), False),
            ("linux.library_list", "injection", "mapped library baseline", ("linux.pslist",), False),
            ("linux.pscallstack", "injection", "thread call-stack context", ("linux.pslist",), False),
            ("linux.malware.process_spoofing", "injection", "task-name/executable discrepancies", ("linux.pslist",), False),
            ("linux.vmayarascan", "injection", "analyst-supplied YARA over VMAs", ("linux.pslist",), False),
        ),
        "mac": (
            ("mac.malfind", "injection", "private executable mappings", ("mac.pslist",), False),
            ("mac.proc_maps", "injection", "mapping and protection context", ("mac.pslist",), False),
        ),
    },
    "credentials": {
        "windows": (
            ("windows.registry.hivescan", "credentials", "scan registry hives", ("windows.info",), True),
            ("windows.registry.hivelist", "credentials", "registry hive inventory", ("windows.info",), True),
            ("windows.registry.hashdump", "credentials", "SAM account verifier extraction", ("windows.registry.hivelist",), True),
            ("windows.registry.cachedump", "credentials", "cached domain verifier extraction", ("windows.registry.hivelist",), True),
            ("windows.registry.lsadump", "credentials", "LSA secret extraction", ("windows.registry.hivelist",), True),
            ("windows.malware.skeleton_key_check", "credentials", "LSASS skeleton-key checks", ("windows.pslist",), True),
        ),
        "linux": (
            ("linux.malware.check_creds", "credentials", "shared credential-structure anomalies", ("linux.pslist",), True),
            ("linux.bash", "credentials", "shell history evidence (not password recovery)", ("linux.pslist",), True),
            ("linux.envars", "credentials", "credential-related environment evidence", ("linux.pslist",), True),
        ),
        "mac": (
            ("mac.bash", "credentials", "shell history evidence (not password recovery)", ("mac.pslist",), True),
            ("mac.lsof", "credentials", "open keychain/database files", ("mac.pslist",), True),
        ),
    },
    "kernel": {
        "windows": (
            ("windows.modules", "kernel", "linked kernel modules", ("windows.info",), False),
            ("windows.modscan", "kernel", "scanned kernel modules", ("windows.info",), False),
            ("windows.callbacks", "kernel", "registered callbacks", ("windows.info",), False),
            ("windows.driverirp", "kernel", "driver dispatch tables", ("windows.info",), False),
            ("windows.ssdt", "kernel", "system service table", ("windows.info",), False),
        ),
        "linux": (
            ("linux.lsmod", "kernel", "linked modules", ("banners",), False),
            ("linux.malware.modxview", "kernel", "module cross-view", ("linux.lsmod",), False),
            ("linux.malware.check_syscall", "kernel", "syscall-table integrity", ("banners",), False),
            ("linux.malware.check_modules", "kernel", "module-list integrity", ("banners",), False),
            ("linux.malware.netfilter", "kernel", "netfilter hook inspection", ("banners",), False),
        ),
        "mac": (
            ("mac.lsmod", "kernel", "kernel extension inventory", ("banners",), False),
            ("mac.check_syscall", "kernel", "syscall-table integrity", ("banners",), False),
            ("mac.check_trap_table", "kernel", "Mach trap-table integrity", ("banners",), False),
            ("mac.kauth_listeners", "kernel", "KAUTH listeners", ("banners",), False),
        ),
    },
}


def build_memory_plan(
    os_family: str,
    metadata: Mapping[str, object],
    goals: Sequence[str] = ("handles", "injection", "credentials", "kernel"),
) -> MemoryDepthPlan | None:
    """Build a dependency-ordered, non-executable deep-memory plan."""

    if not isinstance(goals, Sequence) or isinstance(goals, (str, bytes)) or len(goals) > 16:
        return None
    profile = select_profile(os_family, metadata)
    if profile is None:
        return None
    selected = tuple(dict.fromkeys(_clean_text(goal, 64).casefold() for goal in goals))
    if not selected or any(goal not in _GOAL_STEPS for goal in selected):
        return None
    definitions = list(_BASE_STEPS[profile.os_family])
    for goal in selected:
        definitions.extend(_GOAL_STEPS[goal][profile.os_family])
    inventory = installed_plugin_modules()
    steps: list[MemoryPlanStep] = []
    seen: set[str] = set()
    for plugin, phase, purpose, dependencies, sensitive in definitions:
        if plugin in seen:
            continue
        seen.add(plugin)
        arguments = (("symbol_hint", profile.symbol_hint),) if phase == "identify" else ()
        steps.append(MemoryPlanStep(plugin, phase, purpose, dependencies, arguments,
                                    plugin in inventory, sensitive))
    unavailable = tuple(step.plugin for step in steps if not step.available)
    notes = (
        "declarative offline plan only; this module never invokes Volatility",
        "memory image parsing and plugin execution belong in the repository Docker sandbox",
        "use only locally supplied symbol tables; do not fetch symbols from this plan",
        "credential steps are sensitive and results must remain inside the squad",
    )
    return MemoryDepthPlan(profile, selected, tuple(steps), unavailable, notes)


def _key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _json_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_load(text: str) -> object:
    return json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_json_constant)


def _json_depth_ok(text: str) -> bool:
    """Bound nesting/container dimensions before the decoder expands them."""

    # Each frame is [opening delimiter, separator count, has content].  JSON objects are bounded
    # to the same field count accepted by normalization, and every JSON array is bounded before
    # it can expand beyond the global row cap.
    stack: list[list[object]] = []
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character in "[{":
            if stack:
                stack[-1][2] = True
            stack.append([character, 0, False])
            if len(stack) > MAX_JSON_DEPTH:
                return False
        elif character in "]}":
            if not stack or (character == "]" and stack[-1][0] != "[") or (
                character == "}" and stack[-1][0] != "{"
            ):
                return False
            stack.pop()
        elif character == "," and stack:
            stack[-1][1] = int(stack[-1][1]) + 1
            limit = MAX_ROWS if stack[-1][0] == "[" else MAX_FIELDS
            if int(stack[-1][1]) >= limit:
                return False
        elif not character.isspace() and stack:
            stack[-1][2] = True
    return not quoted and not stack


def _skip_json_space(text: str, position: int) -> int:
    while position < len(text) and text[position] in " \t\r\n":
        position += 1
    return position


def _strict_json_array_rows(text: str) -> list[Mapping[str, object]] | None:
    """Incrementally decode a top-level row array without materializing past MAX_ROWS."""

    decoder = json.JSONDecoder(object_pairs_hook=_json_pairs, parse_constant=_json_constant)
    position = _skip_json_space(text, 0)
    if position >= len(text) or text[position] != "[":
        return None
    position += 1
    rows: list[Mapping[str, object]] = []
    while True:
        position = _skip_json_space(text, position)
        if position >= len(text):
            return None
        if text[position] == "]":
            position = _skip_json_space(text, position + 1)
            return rows if rows and position == len(text) else None
        if len(rows) >= MAX_ROWS:
            return None
        try:
            item, position = decoder.raw_decode(text, position)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None
        if not isinstance(item, Mapping) or not item or len(item) > MAX_FIELDS:
            return None
        rows.append(item)
        position = _skip_json_space(text, position)
        if position >= len(text):
            return None
        if text[position] == ",":
            position = _skip_json_space(text, position + 1)
            if position >= len(text) or text[position] == "]":
                return None
            continue
        if text[position] != "]":
            return None


def _strict_json_rows(text: str) -> list[Mapping[str, object]] | None:
    if not _json_depth_ok(text):
        return None
    if text.lstrip().startswith("["):
        return _strict_json_array_rows(text)
    try:
        obj = _json_load(text)
    except json.JSONDecodeError:
        rows: list[Mapping[str, object]] = []
        for line in io.StringIO(text):
            if not line.strip():
                continue
            if len(rows) >= MAX_ROWS:
                return None
            try:
                item = _json_load(line)
            except (json.JSONDecodeError, ValueError, RecursionError):
                return None
            if not isinstance(item, Mapping) or not item or len(item) > MAX_FIELDS:
                return None
            rows.append(item)
        return rows or None
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, Mapping):
        return None
    if not obj or len(obj) > MAX_FIELDS:
        return None
    rows = obj.get("rows")
    if rows is None:
        for key in ("data", "records", "results"):
            if isinstance(obj.get(key), list):
                rows = obj[key]
                break
    if rows is None:
        return [obj]
    if not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS:
        return None
    columns = obj.get("columns")
    if all(isinstance(row, Mapping) for row in rows):
        return rows if all(row and len(row) <= MAX_FIELDS for row in rows) else None
    if not isinstance(columns, list) or not 2 <= len(columns) <= MAX_FIELDS:
        return None
    names = []
    for column in columns:
        if isinstance(column, str):
            name = column
        elif isinstance(column, Mapping):
            name = column.get("name") or column.get("Name")
        else:
            return None
        cleaned = _clean_text(name, 257)
        if not cleaned or len(cleaned) > 256:
            return None
        names.append(cleaned)
    if len(set(names)) != len(names):
        return None
    converted = []
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) != len(names):
            return None
        converted.append(dict(zip(names, row)))
    return converted


def _csv_body_dimensions_ok(text: str, expected_fields: int) -> bool:
    """Validate CSV body dimensions without allocating row/field collections."""

    start, unquoted, quoted, after_quote = range(4)
    state = start
    fields = 1
    rows = 0
    position = 0
    row_has_data = False
    while position < len(text):
        character = text[position]
        if state == quoted:
            if character == '"':
                state = after_quote
            row_has_data = True
            position += 1
            continue
        if state == after_quote:
            if character == '"':
                state = quoted
                position += 1
                continue
            if character not in {",", "\r", "\n"}:
                return False
        elif character == '"':
            if state != start:
                return False
            state = quoted
            row_has_data = True
            position += 1
            continue
        if character == ",":
            fields += 1
            if fields > expected_fields:
                return False
            state = start
            row_has_data = True
        elif character in {"\r", "\n"}:
            if row_has_data or fields > 1:
                if fields != expected_fields:
                    return False
                rows += 1
                if rows > MAX_ROWS:
                    return False
            fields = 1
            state = start
            row_has_data = False
            if character == "\r" and position + 1 < len(text) and text[position + 1] == "\n":
                position += 1
        else:
            state = unquoted
            row_has_data = True
        position += 1
    if state in {quoted, after_quote}:
        # A closing quote at EOF is valid; an unterminated quoted field is not.
        if state == quoted:
            return False
    if row_has_data or fields > 1:
        if fields != expected_fields:
            return False
        rows += 1
    return 0 < rows <= MAX_ROWS


def _strict_csv_rows(text: str) -> list[Mapping[str, object]] | None:
    # Volatility headers are a single physical line.  Reject delimiter/header bombs before the
    # csv module expands them into a potentially enormous field-name list.
    line_end_candidates = [position for position in (text.find("\n"), text.find("\r")) if position >= 0]
    if not line_end_candidates:
        return None
    header_end = min(line_end_candidates)
    if header_end <= 0 or header_end > MAX_HEADER_TEXT:
        return None
    header_text = text[:header_end]
    if header_text.count(",") + 1 > MAX_FIELDS:
        return None
    try:
        header = next(csv.reader([header_text], strict=True))
        if not 2 <= len(header) <= MAX_FIELDS:
            return None
        body_start = header_end + 1
        if text[header_end] == "\r" and body_start < len(text) and text[body_start] == "\n":
            body_start += 1
        if not _csv_body_dimensions_ok(text[body_start:], len(header)):
            return None
        reader = csv.DictReader(io.StringIO(text), strict=True)
        fieldnames = reader.fieldnames
        if not fieldnames or not 2 <= len(fieldnames) <= MAX_FIELDS:
            return None
        if len(set(fieldnames)) != len(fieldnames):
            return None
        if any(not name or len(name) > 256 for name in fieldnames):
            return None
        if len({_key(name) for name in fieldnames}) != len(fieldnames):
            return None
        rows: list[Mapping[str, object]] = []
        for row in reader:
            if len(rows) >= MAX_ROWS:
                return None
            if None in row or any(value is None for value in row.values()):
                return None
            rows.append(row)
    except (csv.Error, TypeError):
        return None
    return rows or None


def _parse_integer(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 0xFFFFFFFFFFFFFFFF else None
    text = _clean_text(value, 128).replace("`", "")
    if not text or text.casefold() in {"n/a", "none", "-", "unreadable"}:
        return None
    try:
        number = int(text, 16 if text.casefold().startswith("0x") else 10)
    except ValueError:
        return None
    return number if 0 <= number <= 0xFFFFFFFFFFFFFFFF else None


def _first(row: Mapping[str, object], names: Sequence[str]) -> object | None:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return None


def _has_value(row: Mapping[str, object], names: Sequence[str]) -> bool:
    return any(name in row and row[name] not in (None, "") for name in names)


def _plugin_kind(plugin: str) -> str:
    leaf = plugin.rsplit(".", 1)[-1]
    if leaf in {"pslist", "psscan", "pstree", "psxview", "pidhashtable", "proc", "psaux"}:
        return "process"
    if leaf in {"handles", "lsof", "ptrace", "joblinks"}:
        return "handle"
    if leaf in {"privileges", "capabilities"}:
        return "security"
    if leaf in {
        "malfind", "vadinfo", "vadwalk", "ldrmodules", "hollowprocesses",
        "processghosting", "process_spoofing",
    }:
        return "injection"
    if leaf in {"threads", "thrdscan", "suspicious_threads", "suspended_threads", "pscallstack"}:
        return "thread"
    if leaf in {"dlllist", "modules", "modscan", "lsmod", "library_list", "proc_maps"}:
        return "module"
    if leaf in {"hashdump", "cachedump", "lsadump"}:
        return "credential"
    if leaf in {"skeleton_key_check", "check_creds"}:
        return "anomaly"
    if leaf in {"netscan", "netstat", "sockstat", "sockscan"}:
        return "network"
    if leaf in {"filescan", "dumpfiles", "list_files"}:
        return "file"
    return "generic"


_PID_KEYS = ("pid", "process_id", "processid", "uniqueprocessid", "tgid")
_PPID_KEYS = ("ppid", "parent_pid", "parentpid", "inheritedfromuniqueprocessid", "parent")
_TID_KEYS = ("tid", "thread_id", "threadid", "unique_thread")
_NAME_KEYS = ("process", "imagefilename", "image_file_name", "comm", "name", "task", "image")
_ADDRESS_KEYS = (
    "start", "start_address", "startaddress", "address", "offset", "offset_v", "base",
    "base_address", "baseaddress", "handle", "cred_v_addr", "credvaddr",
)
_END_KEYS = ("end", "end_address", "endaddress", "end_vpn")
_PATH_KEYS = (
    "path", "file", "file_path", "filepath", "filename", "mapped_file", "mappedpath",
    "module", "full_path", "vad_path", "exe_path", "name",
)
_TYPE_KEYS = ("type", "object_type", "objecttype")
_PROTECT_KEYS = ("protection", "protect", "permissions", "flags")
_ACCESS_KEYS = ("granted_access", "access", "access_mask", "grantedaccess")
_TARGET_PID_KEYS = ("target_pid", "targetpid", "object_pid", "objectpid")
_RELATION_TID_KEYS = ("tracer_tid", "tracee_tid")


def _normalize_row(plugin: str, family: str, item: Mapping[str, object]) -> MemoryRecord | None:
    if not item or len(item) > MAX_FIELDS:
        return None
    row: dict[str, object] = {}
    fields: list[tuple[str, str]] = []
    for original, value in item.items():
        key = _key(original)
        if not key or key in row:
            return None
        if isinstance(value, str) and "\x00" in value:
            return None
        if isinstance(value, (dict, list, tuple)):
            try:
                text = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
            except (TypeError, ValueError):
                return None
        else:
            text = _clean_text(value, MAX_FIELD_TEXT + 1)
        if len(text) > MAX_FIELD_TEXT:
            return None
        row[key] = value
        fields.append((key, text))
    pid = _parse_integer(_first(row, _PID_KEYS))
    ppid = _parse_integer(_first(row, _PPID_KEYS))
    tid = _parse_integer(_first(row, _TID_KEYS))
    semantic_limits = (
        (_NAME_KEYS, 1024), (_PATH_KEYS, 4096), (_TYPE_KEYS, 256),
        (_PROTECT_KEYS, 512),
    )
    for names, cap in semantic_limits:
        supplied = _first(row, names)
        if supplied is not None and len(_clean_text(supplied, cap + 1)) > cap:
            return None
    process = _clean_text(_first(row, _NAME_KEYS), 1024)
    address = _parse_integer(_first(row, _ADDRESS_KEYS))
    end = _parse_integer(_first(row, _END_KEYS))
    path = _clean_text(_first(row, _PATH_KEYS), 4096)
    object_type = _clean_text(_first(row, _TYPE_KEYS), 256)
    protection = _clean_text(_first(row, _PROTECT_KEYS), 512)
    access = _parse_integer(_first(row, _ACCESS_KEYS))
    target_pid = _parse_integer(_first(row, _TARGET_PID_KEYS))
    # Numeric fields are optional in several renderers, but a supplied malformed value must not
    # silently become ``None`` and pass a different structural branch.
    for names, parsed in (
        (_PID_KEYS, pid), (_PPID_KEYS, ppid), (_TID_KEYS, tid), (_ADDRESS_KEYS, address),
        (_END_KEYS, end), (_ACCESS_KEYS, access),
        (_TARGET_PID_KEYS, target_pid),
    ):
        if _has_value(row, names) and parsed is None:
            return None
    for relation_key in _RELATION_TID_KEYS:
        if _has_value(row, (relation_key,)) and _parse_integer(row[relation_key]) is None:
            marker = _clean_text(row[relation_key], 64).casefold()
            if marker not in {"n/a", "none", "-", "unreadable", "not available"}:
                return None
    if end is not None and address is not None and end < address:
        return None
    kind = _plugin_kind(plugin)
    if kind == "process" and (pid is None or not process):
        return None
    if kind == "handle":
        ptrace_fields = any(key in row for key in ("tracer_tid", "tracee_tid"))
        if pid is None or not (object_type or path or address is not None or ptrace_fields):
            return None
    if kind in {"injection", "thread"} and ((pid is None and tid is None) or address is None):
        # A few detector renderers expose checked evidence rather than an address.
        values = dict(fields)
        leaf = plugin.rsplit(".", 1)[-1]
        explicit = any(_truthy(values.get(key, "")) for key in (
            "suspicious", "result", "detected", "cmdline_spoofed", "comm_spoofed", "exe_deleted",
        ))
        detector_note = leaf == "hollowprocesses" and bool(
            values.get("note") or values.get("notes") or values.get("reason")
        )
        structured_spoofing_row = leaf == "process_spoofing" and pid is not None and bool(process or path)
        if not (explicit or detector_note or structured_spoofing_row):
            return None
    if kind == "module" and not (path or process or address is not None):
        return None
    if kind == "security" and ((pid is None and tid is None) or not process):
        return None
    if kind == "credential" and not any(key in dict(fields) for key in (
        "hash", "ntlm", "nt_hash", "nthash", "lmhash", "secret", "hex",
        "cached_hash", "value",
    )):
        return None
    if kind == "anomaly" and pid is None and address is None:
        return None
    if kind == "network" and pid is None and address is None and not path:
        return None
    if kind == "file" and address is None and not path:
        return None
    if kind == "generic" and pid is None and address is None and not (process or path):
        return None
    return MemoryRecord(plugin, family, kind, pid, ppid, tid, process, address, end, path,
                        object_type, protection, access, tuple(sorted(fields)))


def parse_volatility_output(
    data: object,
    plugin: str,
    *,
    os_family: str | None = None,
    format_hint: str | None = None,
) -> tuple[MemoryRecord, ...]:
    """Strictly normalize complete supplied Volatility JSON/JSONL/CSV output."""

    if not isinstance(data, (bytes, bytearray, memoryview)) or not isinstance(plugin, str):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_INPUT or b"\x00" in raw:
        return ()
    plugin_name = plugin.strip().casefold()
    if not re.fullmatch(r"(?:windows|linux|mac)(?:\.[a-z0-9_]+)+|banners|yarascan", plugin_name):
        return ()
    inventory = installed_plugin_modules()
    if plugin_name not in inventory and plugin_name not in {"banners", "yarascan"}:
        return ()
    inferred = plugin_name.split(".", 1)[0] if "." in plugin_name else ""
    family = (os_family or inferred).strip().casefold() if isinstance(os_family or inferred, str) else ""
    if family == "darwin":
        family = "mac"
    if family not in {"windows", "linux", "mac"} or inferred and inferred != family:
        return ()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ()
    hint = (format_hint or "").strip().casefold()
    if hint not in {"", "json", "jsonl", "ndjson", "csv"}:
        return ()
    if hint == "csv" or (not hint and not text.lstrip().startswith(("{", "["))):
        rows = _strict_csv_rows(text)
    else:
        rows = _strict_json_rows(text)
    if not rows or len(rows) > MAX_ROWS:
        return ()
    out = []
    for item in rows:
        record = _normalize_row(plugin_name, family, item)
        if record is None:
            return ()
        out.append(record)
    return tuple(out)


def _fields(record: MemoryRecord) -> dict[str, str]:
    return dict(record.fields)


def _truthy(value: object) -> bool:
    return _clean_text(value, 64).casefold() in {"true", "yes", "1", "y", "detected", "suspicious"}


def _records(records: Iterable[MemoryRecord]) -> tuple[MemoryRecord, ...] | None:
    out = []
    try:
        iterator = iter(records)
    except Exception:
        return None
    inventory = installed_plugin_modules()
    try:
        for record in iterator:
            if not isinstance(record, MemoryRecord):
                return None
            if record.plugin not in inventory and record.plugin not in {"banners", "yarascan"}:
                return None
            if record.os_family not in {"windows", "linux", "mac"}:
                return None
            inferred = record.plugin.split(".", 1)[0] if "." in record.plugin else ""
            if inferred and inferred != record.os_family:
                return None
            if record.kind != _plugin_kind(record.plugin):
                return None
            try:
                original = dict(record.fields)
            except (TypeError, ValueError):
                return None
            if len(original) != len(record.fields):
                return None
            rebuilt = _normalize_row(record.plugin, record.os_family, original)
            if rebuilt != record:
                return None
            out.append(record)
            if len(out) > MAX_RECORDS_ANALYZED:
                return None
    except Exception:
        # Supplied iterables are untrusted too.  Never emit partial analysis if iteration fails.
        return None
    return tuple(out)


def analyze_process_crossview(records: Iterable[MemoryRecord]) -> tuple[MemoryFinding, ...]:
    """Find checked cross-view, PID/name, and orphan-parent discrepancies."""

    rows = _records(records)
    if not rows:
        return ()
    findings: list[MemoryFinding] = []
    by_family: dict[str, list[MemoryRecord]] = {}
    for record in rows:
        if record.kind == "process":
            by_family.setdefault(record.os_family, []).append(record)
    for family, items in by_family.items():
        primary_names = {"windows.pslist", "linux.pslist", "mac.pslist"}
        scan_names = {"windows.psscan", "linux.psscan", "linux.pidhashtable"}
        primary_plugins = {item.plugin for item in items if item.plugin in primary_names}
        scan_plugins = {item.plugin for item in items if item.plugin in scan_names}
        primary = {(item.pid, item.process.casefold()): item for item in items if item.plugin in primary_names}
        scan = {(item.pid, item.process.casefold()): item for item in items if item.plugin in scan_names}
        if primary_plugins and scan_plugins:
            for key, record in sorted(scan.items(), key=lambda pair: (pair[0][0] or -1, pair[0][1])):
                if key not in primary:
                    findings.append(MemoryFinding(
                        "scan-only-process", family, record.pid, record.process, 0.86,
                        (record.plugin, f"absent from {','.join(sorted(primary_plugins))}"),
                        (("interpretation", "hidden, terminated, or unlinked process candidate"),),
                    ))
        # psxview rows carry explicit view booleans; require a positive scan and negative list.
        for record in items:
            if not record.plugin.endswith("psxview"):
                continue
            values = _fields(record)
            list_value = values.get("pslist", values.get("pslist_psactiveprocesshead", ""))
            scan_value = values.get("psscan", values.get("psscan_poolscan", ""))
            if _truthy(scan_value) and list_value and not _truthy(list_value):
                findings.append(MemoryFinding(
                    "cross-view-hidden-process", family, record.pid, record.process, 0.95,
                    (record.plugin, "psscan=true", "pslist=false"),
                ))
        # Same PID with two names across independent views is concrete reuse/tampering evidence.
        names_by_pid: dict[int, dict[str, set[str]]] = {}
        independent_views = primary_names | scan_names | {"windows.malware.psxview"}
        for item in items:
            if item.plugin not in independent_views:
                continue
            if item.pid is not None:
                names_by_pid.setdefault(item.pid, {}).setdefault(item.process.casefold(), set()).add(item.plugin)
        for pid, names in names_by_pid.items():
            plugins = set().union(*names.values()) if names else set()
            if len(names) > 1 and len(plugins) > 1:
                findings.append(MemoryFinding(
                    "pid-name-conflict", family, pid, " / ".join(sorted(names)), 0.9,
                    tuple(sorted(plugins)),
                ))
        # Parent check only against a complete active-list view.
        active = [item for item in items if item.plugin in primary_names]
        if active:
            active_pids = {item.pid for item in active if item.pid is not None}
            for item in active:
                if item.ppid not in (None, 0, 4) and item.ppid not in active_pids:
                    findings.append(MemoryFinding(
                        "orphan-parent", family, item.pid, item.process, 0.72,
                        (item.plugin, f"parent pid {item.ppid} absent from active list"),
                    ))
    return _dedupe_findings(findings)


_SENSITIVE_PATHS = (
    "/windows/system32/config/sam", "/windows/system32/config/security",
    "/windows/ntds/ntds.dit", "/etc/shadow", "/etc/gshadow", "/login data",
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/var/db/dslocal/nodes/default/users/",
)


def analyze_handles(records: Iterable[MemoryRecord]) -> tuple[MemoryFinding, ...]:
    """Correlate supplied handle rows with sensitive targets and injection rights."""

    rows = _records(records)
    if not rows:
        return ()
    processes = {(record.os_family, record.pid): record.process for record in rows
                 if record.kind == "process" and record.pid is not None}
    findings = []
    for record in rows:
        if record.kind not in {"handle", "security"} or record.pid is None:
            continue
        values = _fields(record)
        leaf = record.plugin.rsplit(".", 1)[-1]
        if leaf == "privileges":
            privilege = (values.get("privilege") or values.get("name") or "").casefold()
            attributes = set(re.findall(r"[a-z]+", values.get("attributes", "").casefold()))
            dangerous = {
                "sedebugprivilege", "setcbprivilege", "seimpersonateprivilege",
                "seassignprimarytokenprivilege", "seloaddriverprivilege",
                "sebackupprivilege", "serestoreprivilege",
            }
            if privilege in dangerous and "enabled" in attributes:
                findings.append(MemoryFinding(
                    "dangerous-enabled-privilege", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.9,
                    (record.plugin, privilege, "enabled"),
                ))
            continue
        if leaf == "capabilities":
            effective = values.get("cap_effective", "").upper()
            dangerous_caps = tuple(capability for capability in (
                "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH", "CAP_SETUID",
                "CAP_SETGID",
            ) if re.search(rf"(?<![A-Z0-9_]){capability}(?![A-Z0-9_])", effective))
            if dangerous_caps:
                findings.append(MemoryFinding(
                    "dangerous-effective-capability", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.9,
                    (record.plugin, *dangerous_caps),
                ))
            continue
        if leaf == "ptrace":
            tracer = _parse_integer(values.get("tracer_tid"))
            tracee = _parse_integer(values.get("tracee_tid"))
            if tracer is not None or tracee is not None:
                relation = f"tracer={tracer}" if tracer is not None else f"tracee={tracee}"
                findings.append(MemoryFinding(
                    "ptrace-relationship", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.88,
                    (record.plugin, relation),
                ))
            continue
        normalized_path = re.sub(r"/+", "/", record.path.replace("\\", "/")).casefold()
        file_like = record.object_type.casefold() in {"", "file", "vnode", "reg", "regular"}
        if file_like and normalized_path and any(marker in normalized_path for marker in _SENSITIVE_PATHS):
            findings.append(MemoryFinding(
                "credential-file-handle", record.os_family, record.pid,
                processes.get((record.os_family, record.pid), record.process), 0.94,
                (record.plugin, record.path), (("object_type", record.object_type),),
            ))
        target_pid = _parse_integer(values.get("target_pid") or values.get("targetpid") or values.get("object_pid"))
        target_name = (values.get("target_process") or values.get("targetprocess") or
                       values.get("target_name") or values.get("targetname") or "")
        if not target_name and target_pid is not None:
            target_name = processes.get((record.os_family, target_pid), "")
        target_name = _clean_text(target_name, 512).casefold()
        object_type = record.object_type.casefold()
        access = record.access or 0
        # Windows Process and Thread objects use different access-bit namespaces.  Process
        # injection needs VM_OPERATION (0x8) + VM_WRITE (0x20), with CREATE_THREAD (0x2) for a
        # non-sensitive target.  Applying these bits to Thread objects creates false positives.
        process_injection_mask = access & 0x28 == 0x28
        sensitive_target = target_name in {"lsass.exe", "winlogon.exe", "securityd", "opendirectoryd"}
        if record.os_family == "windows" and object_type == "process" \
                and process_injection_mask and (sensitive_target or access & 0x2):
            findings.append(MemoryFinding(
                "injection-capable-handle", record.os_family, record.pid,
                processes.get((record.os_family, record.pid), record.process),
                0.91 if sensitive_target else 0.84,
                (record.plugin, f"access=0x{access:x}", f"target={target_name or target_pid or 'unknown'}"),
            ))
        # THREAD_SET_CONTEXT (0x10) plus THREAD_SUSPEND_RESUME (0x2), against an explicitly
        # identified other target, is a checked thread-hijack capability.
        thread_hijack_mask = access & 0x12 == 0x12
        source_name = processes.get((record.os_family, record.pid), record.process).casefold()
        explicit_other_target = (
            target_pid is not None and target_pid != record.pid
        ) or (
            target_pid is None and bool(target_name) and target_name != source_name
        )
        if record.os_family == "windows" and object_type == "thread" \
                and thread_hijack_mask and explicit_other_target:
            findings.append(MemoryFinding(
                "thread-context-hijack-handle", record.os_family, record.pid,
                processes.get((record.os_family, record.pid), record.process),
                0.9 if sensitive_target else 0.85,
                (record.plugin, f"access=0x{access:x}",
                 f"target={target_name or target_pid or 'unknown'}"),
            ))
        if record.os_family == "windows" and object_type == "token" and access & 0x22 == 0x22:
            findings.append(MemoryFinding(
                "token-duplicate-adjust-handle", record.os_family, record.pid,
                processes.get((record.os_family, record.pid), record.process), 0.88,
                (record.plugin, f"access=0x{access:x}"),
            ))
    return _dedupe_findings(findings)


def analyze_injection(records: Iterable[MemoryRecord]) -> tuple[MemoryFinding, ...]:
    """Find injection evidence with plugin-specific protection/list/thread checks."""

    rows = _records(records)
    if not rows:
        return ()
    processes = {(record.os_family, record.pid): record.process for record in rows
                 if record.kind == "process" and record.pid is not None}
    findings = []
    suspicious_ranges: list[MemoryRecord] = []
    for record in rows:
        if record.kind not in {"injection", "module", "thread"}:
            continue
        values = _fields(record)
        leaf = record.plugin.rsplit(".", 1)[-1]
        protection = record.protection.casefold().replace("_", "-")
        writable = "rwx" in protection or "execute-readwrite" in protection or (
            "exec" in protection and "write" in protection)
        dump = " ".join(values.get(key, "") for key in ("hexdump", "hex", "data", "bytes"))
        mz = bool(re.search(r"(?:^|\s)(?:4d\s*5a|4d5a)(?:\s|$)", dump, re.I))
        if leaf == "malfind" and record.address is not None and (writable or mz):
            suspicious_ranges.append(record)
            findings.append(MemoryFinding(
                "private-executable-region", record.os_family, record.pid,
                processes.get((record.os_family, record.pid), record.process),
                0.96 if mz and writable else 0.9,
                (record.plugin, f"address=0x{record.address:x}",
                 f"protection={record.protection or 'unknown'}", "MZ header" if mz else "executable+writable"),
            ))
        if leaf == "ldrmodules":
            checks = [values.get(key, "") for key in (
                "in_load", "inload", "in_init", "ininit", "in_mem", "inmem",
            ) if key in values]
            false_count = sum(_clean_text(value, 32).casefold() in {"false", "no", "0", "n"}
                              for value in checks)
            if len(checks) >= 2 and false_count >= 2 and record.path:
                findings.append(MemoryFinding(
                    "unlinked-module", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.93,
                    (record.plugin, record.path, f"{false_count}/{len(checks)} loader lists absent"),
                ))
        if leaf == "process_spoofing":
            flags = tuple(key for key in ("cmdline_spoofed", "comm_spoofed", "exe_deleted")
                          if _truthy(values.get(key, "")))
            if flags:
                findings.append(MemoryFinding(
                    "process-spoofing-detector", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.9,
                    (record.plugin, *flags),
                ))
        if leaf == "processghosting":
            flags = tuple(key for key in (
                "delete_pending", "deletepending", "delete_on_close", "deleteonclose",
            )
                          if _truthy(values.get(key, "")))
            if flags and record.address is not None and record.path:
                findings.append(MemoryFinding(
                    "processghosting-detector", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.94,
                    (record.plugin, record.path, *flags),
                ))
        if leaf in {"hollowprocesses", "suspicious_threads"}:
            explicit = any(_truthy(values.get(key, "")) for key in ("suspicious", "detected", "result"))
            reason = (values.get("reason") or values.get("note") or values.get("notes") or
                      values.get("details") or "")
            # These plugins emit only rows for checks that fired; a non-empty diagnostic note is
            # therefore direct detector evidence even when the renderer has no Boolean column.
            if explicit or reason:
                findings.append(MemoryFinding(
                    f"{leaf}-detector", record.os_family, record.pid,
                    processes.get((record.os_family, record.pid), record.process), 0.94,
                    (record.plugin, reason or "explicit detector result"),
                ))
    for thread in rows:
        if thread.kind != "thread" or thread.address is None or thread.pid is None:
            continue
        for region in suspicious_ranges:
            end = region.end if region.end is not None else region.address
            if region.os_family == thread.os_family and region.pid == thread.pid \
                    and region.address is not None and end is not None \
                    and region.address <= thread.address <= end:
                findings.append(MemoryFinding(
                    "thread-start-in-suspicious-region", thread.os_family, thread.pid,
                    processes.get((thread.os_family, thread.pid), thread.process), 0.98,
                    (thread.plugin, region.plugin, f"thread=0x{thread.address:x}",
                     f"region=0x{region.address:x}-0x{end:x}"),
                ))
    return _dedupe_findings(findings)


_HEX32 = re.compile(r"(?i)^[0-9a-f]{32}$")
_DCC2 = re.compile(r"(?i)^\$DCC2\$[0-9]+#[^#]{1,256}#[0-9a-f]{32}$")


def credential_artifacts(records: Iterable[MemoryRecord]) -> tuple[CredentialArtifact, ...]:
    """Return only syntax-validated verifier/secret artifacts from credential plugins."""

    rows = _records(records)
    if not rows:
        return ()
    out: list[CredentialArtifact] = []
    for record in rows:
        if record.kind != "credential":
            continue
        values = _fields(record)
        account = _clean_text(values.get("username") or values.get("user") or
                              values.get("account") or values.get("name") or
                              values.get("key"), 512)
        candidate = _clean_text(values.get("ntlm") or values.get("nt_hash") or
                                values.get("nthash") or values.get("cached_hash") or
                                values.get("hash"), 2048)
        if candidate:
            parts = candidate.split(":")
            verifiers = [part for part in parts if _HEX32.fullmatch(part)]
            compact_candidate = re.sub(r"[\s-]", "", candidate)
            if _HEX32.fullmatch(compact_candidate):
                verifiers.append(compact_candidate)
            dcc2 = _DCC2.fullmatch(candidate)
            embedded_account = candidate.split("#", 2)[1] if dcc2 else ""
            if dcc2 and (not account or embedded_account.casefold() == account.casefold()):
                out.append(CredentialArtifact("dcc2", account, candidate, record.plugin,
                                              "DCC2 syntax and 128-bit verifier"))
            elif verifiers and account:
                # In pwdump form the final 32-hex field is the NT verifier.
                verifier = verifiers[-1].lower()
                artifact_kind = "cached-domain-verifier" if record.plugin.endswith("cachedump") else "ntlm"
                out.append(CredentialArtifact(artifact_kind, account, verifier, record.plugin,
                                              "account-bound 128-bit verifier field"))
        secret = _clean_text(values.get("secret") or values.get("value") or
                             values.get("hex"), 4096)
        secret_compact = re.sub(r"[\s:-]", "", secret)
        if account and len(secret_compact) >= 16 and len(secret_compact) % 2 == 0 \
                and re.fullmatch(r"[0-9a-fA-F]+", secret_compact):
            out.append(CredentialArtifact("lsa-secret-bytes", account, secret_compact.lower(),
                                          record.plugin, "explicit even-length hexadecimal secret bytes"))
    unique = {(item.kind, item.account, item.verifier, item.source_plugin): item for item in out}
    return tuple(sorted(unique.values(), key=lambda item: (item.kind, item.account, item.source_plugin)))


def _dedupe_findings(findings: Iterable[MemoryFinding]) -> tuple[MemoryFinding, ...]:
    unique: dict[tuple, MemoryFinding] = {}
    for finding in findings:
        key = (finding.kind, finding.os_family, finding.pid, finding.process,
               finding.evidence, finding.details)
        prior = unique.get(key)
        if prior is None or finding.confidence > prior.confidence:
            unique[key] = finding
    return tuple(sorted(unique.values(), key=lambda item: (
        item.os_family, item.pid if item.pid is not None else -1, item.kind, item.process,
    )))


def analyze_memory(records: Iterable[MemoryRecord]) -> tuple[MemoryFinding, ...]:
    """Run every checked process/handle/injection correlation and deduplicate findings."""

    rows = _records(records)
    if rows is None:
        return ()
    return _dedupe_findings((*analyze_process_crossview(rows), *analyze_handles(rows),
                             *analyze_injection(rows)))


__all__ = [
    "CredentialArtifact", "MemoryDepthPlan", "MemoryFinding", "MemoryPlanStep",
    "MemoryRecord", "ProfileSelection", "analyze_handles", "analyze_injection",
    "analyze_memory", "analyze_process_crossview", "build_memory_plan",
    "credential_artifacts", "installed_plugin_modules", "parse_volatility_output",
    "select_profile",
]
