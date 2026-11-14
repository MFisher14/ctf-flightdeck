"""Inert, pinned plans for tracing one managed or bytecode artifact in its runtime container (B-242).

Everything here is data and pure functions: nothing opens a file, starts a process, imports a
runtime or runs a byte of an artifact. The four parts are the protocol between the engine
(``runtime_trace.py``, which loads this helper by path), the one place that starts a container (``tools/sandbox.py runtime_run``) and
the runner baked into each ``ctf-runtime-*`` image (``docker/runtime/``):

    classify(data, name)            which runtime reads these bytes, and in which image variants
    build_plan(runtime, variant)    the RuntimePlan: image name, runner argv, fuel, time, limits
    request_members(artifact, deps) the (name, bytes) members of the request tar (fixed names)
    parse_trace(stdout, runtime)    the runner's one trace line, validated, as a Trace

A plan always says: no network, no host mount, read-only root, every capability dropped, an
unprivileged user. The artifact reaches the container on stdin and the trace leaves on stdout.
``image`` is a name of ``tools/images.toml``; ``runtime_run`` runs it only when the image carries the
content hash of the files it is built from, and then by its image id, so what was checked is what
runs.

Runtimes: ``wasm`` (wasmtime, fuel in instructions), ``python`` (.pyc on the CPython that wrote it,
fuel in bytecode instructions), ``lua`` (source or bytecode on Lua 5.1 to 5.4 or LuaJIT, fuel in VM
instructions), ``jvm`` (a class or jar), ``dotnet`` (a CIL assembly) and ``node`` (JavaScript or V8
cached data); the last three have no instruction counter, so their fuel is wall time. A trace is
untrusted: it is produced by code running beside the artifact, so every field is bounded and typed
here and nothing in it is ever executed or followed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import io
import json
import re
import struct
from typing import Sequence
import zipfile

SCHEMA = 1
TRACE_MARKER = "@@CTF-RUNTIME-TRACE@@ "
ARTIFACT = "artifact.bin"            # the artifact's fixed name in the request
DEPS = "dep"                         # the folder of dependency members (dep/000.bin ...)
WORK = "/work"                       # the tmpfs the request is unpacked into
ENTRY = "/usr/local/bin/ctf-runtime-entry"

MIN_SECONDS, MAX_SECONDS, DEFAULT_SECONDS = 1, 300, 30
GRACE_SECONDS = 5                    # the container's own limit is the runner's budget plus this
MAX_FUEL = 10 ** 12
DEFAULT_FUEL = {"wasm": 50_000_000, "lua": 20_000_000, "python": 5_000_000}
MAX_PROBES, MAX_PROBE_BYTES = 8, 1024
DEFAULT_EVENTS, MAX_EVENTS = 512, 4096
MAX_ARTIFACT_BYTES = 64 << 20
MAX_DEPS, MAX_REQUEST_BYTES = 32, 96 << 20
MAX_TRACE_BYTES = 4 << 20
MAX_TRACE_STRINGS, MAX_TRACE_ENTRIES, MAX_TRACE_NOTES = 1024, 1024, 256
MAX_TRACE_TEXT = 4096
MAX_ZIP_ENTRIES = 100_000

FUEL_KIND = {"wasm": "instructions", "lua": "instructions", "python": "instructions",
             "jvm": "time", "dotnet": "time", "node": "time"}
RUNTIMES = tuple(FUEL_KIND)
STATUSES = ("ok", "partial", "error")

# (runtime, variant) -> the tools/images.toml name. "" is the runtime's only variant.
PYTHON_VERSIONS = ("3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14")
NODE_VERSIONS = ("24", "22", "20")                     # newest first: the order a .jsc is tried in
LUA_VERSIONS = ("5.4", "5.3", "5.2", "5.1", "luajit")
IMAGES = {("wasm", ""): "runtime-wasm", ("jvm", ""): "runtime-jvm", ("dotnet", ""): "runtime-dotnet"}
IMAGES.update({("python", v): f"runtime-python-{v}" for v in PYTHON_VERSIONS})
IMAGES.update({("node", v): f"runtime-node-{v}" for v in NODE_VERSIONS})
IMAGES.update({("lua", v): "runtime-lua" for v in LUA_VERSIONS})

# The magic word each CPython release writes into a .pyc (bytes 0-1, little-endian).
PYC_MAGIC = {3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11", 3531: "3.12", 3571: "3.13", 3627: "3.14"}
DEFAULT_PYTHON = "3.12"              # for Python source, which any of them reads
LUA_BYTECODE = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}
_LUA_VM = {"5.1": "lua5.1", "5.2": "lua5.2", "5.3": "lua5.3", "5.4": "lua5.4", "luajit": "luajit"}
_CLASS_MAJOR = range(45, 256)        # a Java class file's major version (a fat Mach-O has 1..44 here)

_RUNNER = {
    "wasm": ("python3", "-I", "/opt/runner/trace_runner.py"),
    "python": ("python3", "-I", "-B", "/opt/runner/trace_runner.py"),
    "jvm": ("java", "-XX:+UseSerialGC", "-Xmx384m", "-Xss2m", "-XX:TieredStopAtLevel=1",
            "-XX:+PerfDisableSharedMem", "-Djava.awt.headless=true", "-cp", "/opt/runner", "TraceRunner"),
    "dotnet": ("dotnet", "/opt/runner/TraceRunner.dll"),
    "node": ("node", "--max-old-space-size=384", "/opt/runner/trace_runner.js"),
}


class PlanError(ValueError):
    """A plan or request that must not be built: an unknown runtime or variant, or a value out of bounds."""


class TraceError(ValueError):
    """The runner's output is not one valid trace: str() says what is wrong with it."""


# --------------------------------------------------------------------------------------- classify
@dataclass(frozen=True)
class Target:
    """What reads an artifact: ``runtime``, the image ``variants`` to try in order, the ``kind`` of
    file. ``variants`` is empty when the bytes are recognised but no image reads them; ``note`` then
    says which version they need."""
    runtime: str
    variants: tuple[str, ...]
    kind: str
    note: str = ""


def _is_cil_assembly(data: bytes) -> bool:
    """A PE whose CLR runtime header directory (index 14) is set: managed code, not a native image."""
    # Every field is read as a slice, so a truncated file gives a short slice and False, never an error.
    lfanew = data[0x3C:0x40]
    if data[:2] != b"MZ" or len(lfanew) != 4:
        return False
    pe = int.from_bytes(lfanew, "little")
    if data[pe:pe + 4] != b"PE\x00\x00":
        return False
    opt = pe + 24                                             # the optional header follows the COFF header
    dirs = {b"\x0b\x01": 96, b"\x0b\x02": 112}.get(data[opt:opt + 2])    # PE32 / PE32+: where the directories start
    if dirs is None:
        return False
    clr = data[opt + dirs + 14 * 8:opt + dirs + 15 * 8]
    if len(clr) != 8:
        return False
    rva, size = struct.unpack("<II", clr)
    return rva != 0 and size != 0


def _is_jar(data: bytes) -> bool:
    """A zip whose central directory names a ``.class`` entry (an EPUB or APK is not a jar)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return any(i.filename.endswith(".class") for i in z.infolist()[:MAX_ZIP_ENTRIES])
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError, struct.error):
        return False


def classify(data: bytes, name: str = "", *, source: bool = False) -> Target | None:
    """The runtime that reads ``data``, or None when no adapter does. Bytecode and binary kinds are
    told by their magic numbers; source text (``.js``/``.cjs``, ``.lua``, ``.py``) only by the file
    name and only with ``source=True``, because a readable script needs no trace unless asked."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("classify takes the artifact's bytes")
    data = bytes(data)
    low = name.lower()
    if data[:4] == b"\x00asm":
        if data[4:8] == b"\x01\x00\x00\x00":
            return Target("wasm", ("",), "module")
        return Target("wasm", (), "module", "not a core WebAssembly module, version 1 (a component, or "
                                              f"version bytes {data[4:8].hex()})")
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data[6:8]) == 2 and int.from_bytes(data[6:8], "big") in _CLASS_MAJOR:
        return Target("jvm", ("",), "class")
    if data[:2] == b"PK" and _is_jar(data):
        return Target("jvm", ("",), "jar")
    if _is_cil_assembly(data):
        return Target("dotnet", ("",), "assembly")
    if len(data[:16]) == 16 and data[2:4] == b"\r\n":      # a .pyc header is 16 bytes (3.7+)
        word = int.from_bytes(data[:2], "little")
        if word in PYC_MAGIC:
            return Target("python", (PYC_MAGIC[word],), "pyc")
        if 3000 <= word < 4000:
            return Target("python", (), "pyc", f"no image reads .pyc magic {word} (images: "
                                                + ", ".join(f"{m}={v}" for m, v in sorted(PYC_MAGIC.items())) + ")")
    if data[:4] == b"\x1bLua" and len(data[4:5]) == 1:
        version = LUA_BYTECODE.get(data[4])
        if version:
            return Target("lua", (version,), "bytecode")
        return Target("lua", (), "bytecode", f"no interpreter in the image reads Lua bytecode version 0x{data[4]:02x}")
    if data[:3] == b"\x1bLJ":
        return Target("lua", ("luajit",), "bytecode")
    # V8 cached data: a 24-byte header whose first word is 0xC0DExxxx (little-endian)
    if low.endswith(".jsc") and len(data[:24]) == 24 and data[2:4] == b"\xde\xc0":
        return Target("node", NODE_VERSIONS, "jsc")
    if source:
        if low.endswith((".js", ".cjs")):
            return Target("node", (NODE_VERSIONS[0],), "source")
        if low.endswith(".lua"):
            return Target("lua", (LUA_VERSIONS[0],), "source")
        if low.endswith(".py"):
            return Target("python", (DEFAULT_PYTHON,), "source")
    return None


# ------------------------------------------------------------------------------------------- plan
@dataclass(frozen=True)
class RuntimePlan:
    runtime: str
    variant: str
    image: str                          # a tools/images.toml name
    argv: tuple[str, ...]               # the runner and its arguments, inside the container
    fuel: int                           # instructions; 0 for a runtime whose fuel is time
    fuel_kind: str
    seconds: int                        # the runner's own time budget
    container_seconds: int              # the container is stopped after this (seconds + GRACE_SECONDS)
    probes: tuple[str, ...]             # hex of each probe
    network: str = "none"
    mounts: tuple[str, ...] = ()
    read_only_root: bool = True
    drop_capabilities: tuple[str, ...] = ("ALL",)
    user: str = "10001:10001"
    memory: str = "768m"
    cpus: str = "1"
    pids: int = 96

    def to_dict(self) -> dict:
        return asdict(self)


def _bounded_int(value, low: int, high: int, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise PlanError(f"{what} must be a whole number in {low}..{high}, got {value!r}")
    return value


def build_plan(runtime: str, variant: str = "", *, fuel: int | None = None, seconds: int = DEFAULT_SECONDS,
               probes: Sequence[bytes] = (), max_events: int = DEFAULT_EVENTS) -> RuntimePlan:
    """The plan that traces one artifact with ``runtime`` in its ``variant`` image. PlanError for an
    unknown runtime or variant, a time, fuel or event bound out of range, or too many or too long
    probes."""
    if (runtime, variant) not in IMAGES:
        known = sorted(v for r, v in IMAGES if r == runtime)
        if not known:
            raise PlanError(f"unknown runtime {runtime!r} (known: {', '.join(RUNTIMES)})")
        raise PlanError(f"runtime {runtime!r} has no variant {variant!r} (known: {', '.join(repr(v) for v in known)})")
    seconds = _bounded_int(seconds, MIN_SECONDS, MAX_SECONDS, "seconds")
    max_events = _bounded_int(max_events, 1, MAX_EVENTS, "max_events")
    kind = FUEL_KIND[runtime]
    if kind == "time":
        if fuel not in (None, 0):
            raise PlanError(f"runtime {runtime!r} has no instruction counter: its fuel is `seconds`, not fuel={fuel!r}")
        fuel = 0
    else:
        fuel = _bounded_int(DEFAULT_FUEL[runtime] if fuel is None else fuel, 1, MAX_FUEL, "fuel")
    probes = tuple(probes)
    if len(probes) > MAX_PROBES:
        raise PlanError(f"at most {MAX_PROBES} probes, got {len(probes)}")
    for p in probes:
        if not isinstance(p, (bytes, bytearray)) or len(p) > MAX_PROBE_BYTES:
            raise PlanError(f"a probe is at most {MAX_PROBE_BYTES} bytes")
    runner = (_LUA_VM[variant], "/opt/runner/trace_runner.lua") if runtime == "lua" else _RUNNER[runtime]
    argv = [*runner, "--artifact", f"{WORK}/{ARTIFACT}", "--deps", f"{WORK}/{DEPS}", "--fuel", str(fuel),
            "--seconds", str(seconds), "--max-events", str(max_events)]
    for p in probes:
        argv += ["--probe-hex", bytes(p).hex()]
    return RuntimePlan(runtime=runtime, variant=variant, image=IMAGES[(runtime, variant)], argv=tuple(argv),
                       fuel=fuel, fuel_kind=kind, seconds=seconds, container_seconds=seconds + GRACE_SECONDS,
                       probes=tuple(bytes(p).hex() for p in probes))


def request_members(artifact: bytes, deps: Sequence[bytes] = ()) -> list[tuple[str, bytes]]:
    """The members of the request tar: the artifact under its fixed name, each dependency as
    ``dep/NNN.bin``. No name comes from a delivered file. PlanError when a size or count cap is passed."""
    if not isinstance(artifact, (bytes, bytearray)) or not artifact:
        raise PlanError("the artifact must be non-empty bytes")
    if len(artifact) > MAX_ARTIFACT_BYTES:
        raise PlanError(f"the artifact is {len(artifact)} bytes, over the {MAX_ARTIFACT_BYTES} byte cap")
    deps = list(deps)
    if len(deps) > MAX_DEPS:
        raise PlanError(f"at most {MAX_DEPS} dependencies, got {len(deps)}")
    total = len(artifact) + sum(len(d) for d in deps)
    if total > MAX_REQUEST_BYTES:
        raise PlanError(f"the request is {total} bytes, over the {MAX_REQUEST_BYTES} byte cap")
    return [(ARTIFACT, bytes(artifact))] + [(f"{DEPS}/{i:03d}.bin", bytes(d)) for i, d in enumerate(deps)]


# ------------------------------------------------------------------------------------------ trace
@dataclass(frozen=True)
class Trace:
    runtime: str
    runtime_version: str
    status: str                                   # ok | partial | error
    fuel_kind: str
    fuel_limit: int
    fuel_used: int
    fuel_exhausted: bool
    entries: tuple[tuple[str, str], ...]          # (name, signature) of each entry point
    events: tuple[dict, ...]                      # {"kind": ..., <field>: <text>}
    strings: tuple[str, ...]                      # strings observed at run time
    notes: tuple[str, ...]
    truncated: bool

    def texts(self) -> list[str]:
        """Every piece of text the run produced: the observed strings and each event field."""
        out = list(self.strings)
        for e in self.events:
            out += [v for k, v in e.items() if k != "kind"]
        return out

    def errors(self) -> list[str]:
        """What went wrong, one line each: load and call failures."""
        out = []
        for e in self.events:
            if e["kind"] == "error":
                out.append(f"{e.get('name', '?')}: {e.get('text', '')}".strip())
            elif e["kind"] == "call" and "error" in e:
                out.append(f"{e.get('name', '?')}({e.get('args', '')}): {e['error']}")
        return out

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "runtime": self.runtime, "runtime_version": self.runtime_version,
                "status": self.status,
                "fuel": {"kind": self.fuel_kind, "limit": self.fuel_limit, "used": self.fuel_used,
                         "exhausted": self.fuel_exhausted},
                "entries": [{"name": n, "signature": s} for n, s in self.entries],
                "events": [dict(e) for e in self.events], "strings": list(self.strings),
                "notes": list(self.notes), "truncated": self.truncated}


def _text(value, what: str) -> str:
    if not isinstance(value, str):
        raise TraceError(f"{what} is not a string")
    if len(value) > MAX_TRACE_TEXT:
        raise TraceError(f"{what} is longer than {MAX_TRACE_TEXT} characters")
    return value


def _texts(value, cap: int, what: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TraceError(f"{what} is not a list")
    if len(value) > cap:
        raise TraceError(f"{what} has {len(value)} items, over the cap of {cap}")
    return tuple(_text(v, f"an item of {what}") for v in value)


_KIND = re.compile(r"[a-z_]{1,32}\Z")


def parse_trace(stdout: bytes, runtime: str) -> Trace:
    """The trace in a runner's stdout: the last line that starts with TRACE_MARKER, as a validated
    Trace. TraceError when there is none, it is too large, it is not the schema, or it was written
    by another runtime than ``runtime``."""
    if not isinstance(stdout, (bytes, bytearray)):
        raise TypeError("parse_trace takes the runner's stdout bytes")
    marker = TRACE_MARKER.encode()
    lines = [ln for ln in bytes(stdout).split(b"\n") if ln.startswith(marker)]
    if not lines:
        raise TraceError("the runner printed no trace line")
    body = lines[-1][len(marker):]
    if len(body) > MAX_TRACE_BYTES:
        raise TraceError(f"the trace is {len(body)} bytes, over the {MAX_TRACE_BYTES} byte cap")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        raise TraceError(f"the trace line is not JSON ({type(e).__name__})") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise TraceError(f"the trace is not schema {SCHEMA}")
    if doc.get("runtime") != runtime:
        raise TraceError(f"the trace was written by runtime {doc.get('runtime')!r}, not {runtime!r}")
    status = doc.get("status")
    if status not in STATUSES:
        raise TraceError(f"trace status {status!r} is not one of {', '.join(STATUSES)}")
    fuel = doc.get("fuel")
    if not isinstance(fuel, dict) or fuel.get("kind") != FUEL_KIND[runtime]:
        raise TraceError(f"the trace's fuel is not {FUEL_KIND[runtime]!r} fuel")
    for key in ("limit", "used"):
        if not isinstance(fuel.get(key), int) or isinstance(fuel.get(key), bool) or fuel[key] < 0:
            raise TraceError(f"trace fuel.{key} is not a whole number >= 0")
    if not isinstance(fuel.get("exhausted"), bool) or not isinstance(doc.get("truncated"), bool):
        raise TraceError("trace fuel.exhausted and truncated must be true or false")
    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_TRACE_ENTRIES:
        raise TraceError(f"trace entries is not a list of at most {MAX_TRACE_ENTRIES}")
    entries = []
    for e in raw_entries:
        if not isinstance(e, dict) or set(e) != {"name", "signature"}:
            raise TraceError("a trace entry is not {name, signature}")
        entries.append((_text(e["name"], "an entry name"), _text(e["signature"], "an entry signature")))
    raw_events = doc.get("events")
    if not isinstance(raw_events, list) or len(raw_events) > MAX_EVENTS:
        raise TraceError(f"trace events is not a list of at most {MAX_EVENTS}")
    events = []
    for e in raw_events:
        if not isinstance(e, dict) or not isinstance(e.get("kind"), str) or not _KIND.match(e["kind"]) or len(e) > 8:
            raise TraceError("a trace event is not an object with a kind and at most 7 fields")
        events.append({_text(k, "an event key"): _text(v, f"event field {k!r}") for k, v in e.items()})
    return Trace(runtime=runtime, runtime_version=_text(doc.get("runtime_version"), "runtime_version"),
                 status=status, fuel_kind=fuel["kind"], fuel_limit=fuel["limit"], fuel_used=fuel["used"],
                 fuel_exhausted=fuel["exhausted"], entries=tuple(entries), events=tuple(events),
                 strings=_texts(doc.get("strings"), MAX_TRACE_STRINGS, "strings"),
                 notes=_texts(doc.get("notes"), MAX_TRACE_NOTES, "notes"), truncated=doc["truncated"])


__all__ = ["ARTIFACT", "DEPS", "ENTRY", "FUEL_KIND", "IMAGES", "PlanError", "RUNTIMES", "RuntimePlan", "Target",
           "Trace", "TraceError", "TRACE_MARKER", "build_plan", "classify", "parse_trace", "request_members"]
