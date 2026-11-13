"""What this machine has for local models: `flightdeck models`, and one line of `flightdeck doctor`.

The facts: the OS and architecture (WSL counts as Linux); on macOS the chip (sysctl
machdep.cpu.brand_string) and whether it is Apple Silicon; total memory (macOS: sysctl
hw.memsize; Linux: MemTotal in /proc/meminfo); NVIDIA GPUs and their memory (nvidia-smi, asked
only when it is on PATH); on Linux, AMD and Intel GPUs (the PCI vendor of each
/sys/class/drm/cardN; an AMD card's memory from the amdgpu driver's mem_info_vram_total there,
else from rocm-smi when it is on PATH; an Intel GPU's memory is not read). flightdeck has no
measured results for AMD or Intel GPUs: they are found and said, and the advice does not count
them (model_catalog.budget()). And the local model runtimes: Ollama (the ollama program, and the
models its server has pulled, with the size on disk it gives each), an MLX server
(mlx_lm.server on PATH or the mlx_lm package importable, and the models a server at
mlx_lm.server's port lists), llama.cpp's llama-server, and LM Studio's server.

Every probe has a short timeout, needs no root and contacts nothing but 127.0.0.1: the servers'
addresses are fixed here, and local_only() refuses any other before a request is made. Programs
are found through PATH's absolute folders only, as agent/external.py find_agent finds a
coding-agent CLI: a relative entry ("." or an empty one) is whatever folder flightdeck was
started in, a handout say. A probe that fails, times out or reads something it does not
understand records the fact as unknown, with the reason (Fact.unknown), never a guess.

The probes look at the machine through a Host: its system and architecture names, a program
finder, a command runner, an HTTP getter, a file reader and an import check. RealHost is this
machine; tests give a fake one, so they never depend on the machine they run on.

Of an Ollama server that lists its models, the probe also asks which it has loaded now and the
context it gives each (/api/ps): Ollama says a model's context only while it is loaded
(ollama_context.py).
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from .config import MLX_URL, OLLAMA_URL

GIB = 1024**3
MIB = 1024**2
LOCAL_HOST = "127.0.0.1"
COMMAND_TIMEOUT = 2.0  # seconds for sysctl
# The operating system's own programs, where the system keeps them: found there when a PATH
# leaves their folder out (a cron job, `env -i`, a stripped shell). Only these, only there.
SYSTEM_PROGRAMS = {"Darwin": {"sysctl": "/usr/sbin", "vm_stat": "/usr/bin"}}  # vm_stat: governor.py
GPU_TIMEOUT = 5.0  # seconds for nvidia-smi, whose first call can wait for the driver to load
HTTP_TIMEOUT = 1.0  # seconds for a server on this machine to list its models
MAX_BODY = 4 * 1024 * 1024  # bytes of a model list read at most
MAX_FILE = 1024 * 1024  # bytes of a /proc file read at most
MAX_NAME = 200  # characters a chip's or a GPU's name may have
MAX_MEMORY = 2**50  # bytes (1 PiB): a total memory above this is not one

OLLAMA, MLX, LLAMA_CPP, LM_STUDIO = "ollama", "mlx", "llama.cpp", "lm studio"
RUNTIME_NAMES = {OLLAMA: "Ollama", MLX: "MLX", LLAMA_CPP: "llama.cpp", LM_STUDIO: "LM Studio"}
SERVERS = {  # where each runtime's server lists its models, at its default address on this machine
    OLLAMA: OLLAMA_URL.removesuffix("/v1") + "/api/tags",  # http://127.0.0.1:11434/api/tags
    MLX: MLX_URL + "/models",  # http://127.0.0.1:8080/v1/models (llama-server's default port too)
    LM_STUDIO: "http://127.0.0.1:1234/v1/models",
}
SERVING, DOWN, UNKNOWN = "serving", "down", "unknown"  # a server's state
NVIDIA_QUERY = ("--query-gpu=name,memory.total", "--format=csv,noheader,nounits")  # memory in MiB
AMD, INTEL = "AMD", "Intel"
PCI_VENDORS = {"0x1002": AMD, "0x8086": INTEL}  # the PCI vendor ids looked for (NVIDIA's GPUs are nvidia-smi's to list)
DRM_CARDS = 16  # /sys/class/drm/card0 to card15 are looked at
DRM_FILE = "/sys/class/drm/card{card}/device/{name}"  # vendor, device, mem_info_vram_total (amdgpu: bytes)
ROCM_QUERY = ("--showmeminfo", "vram", "--csv")  # device,VRAM Total Memory (B),VRAM Total Used Memory (B)
RESULTS_FORM = "https://github.com/MFisher14/ctf-flightdeck/issues/new?template=hardware.yml"  # the model results form

_PCI_ID = re.compile(r"0x[0-9a-f]{4}")
_ROCM_ROW = re.compile(r"card([0-9]{1,2}),([0-9]+),[0-9]+")
_DIGITS = re.compile(r"[0-9]+")
_MEMTOTAL = re.compile(r"^MemTotal:[ \t]+([0-9]+)[ \t]+kB[ \t]*$", re.M)


class ProbeError(Exception):
    """A probe got no usable answer; the message says why (it becomes Fact.unknown)."""


class Refused(ProbeError):
    """Nothing is listening at the address: the server is not running."""


class Host(Protocol):
    """How the probes see a machine."""

    system: str  # platform.system(): "Darwin", "Linux", "Windows", ...
    arch: str  # platform.machine(): "arm64", "x86_64", "aarch64", ...

    def which(self, program: str) -> str | None:
        """The program's absolute path, found in PATH's absolute folders only; None if absent."""

    def run(self, argv: Sequence[str], timeout: float) -> str:
        """The command's standard output; ProbeError if it fails, exits non-zero or times out."""

    def get(self, url: str, timeout: float) -> tuple[int, bytes]:
        """(HTTP status, body) of GET url; Refused when nothing listens, ProbeError otherwise."""

    def read(self, path: str) -> str:
        """A file's text; OSError when it cannot be read."""

    def importable(self, module: str) -> bool:
        """Whether this Python can import the module (it is not imported)."""


@dataclass(frozen=True)
class Fact[T]:
    """A probed value, or None and why it is unknown."""

    value: T | None = None
    unknown: str = ""  # the reason, when value is None

    def as_json(self) -> dict:
        value = self.value
        if isinstance(value, tuple):
            value = [item.as_json() if hasattr(item, "as_json") else item for item in value]
        return {"value": value, "unknown": self.unknown or None}


@dataclass(frozen=True)
class Gpu:
    name: str  # as nvidia-smi gives it: untrusted text, fold it before showing it
    memory: int  # bytes

    def as_json(self) -> dict:
        return {"name": self.name, "memory_bytes": self.memory}


@dataclass(frozen=True)
class OtherGpu:
    """An AMD or Intel GPU found on Linux. flightdeck has no measured results for one: it is
    said, and the advice does not count it."""

    vendor: str  # AMD or INTEL
    card: str  # "card0": its name under /sys/class/drm (or as rocm-smi names it)
    device: str = ""  # its PCI device id, "0x744c"; "" when not read
    memory: int | None = None  # bytes of its own memory; None: not read (memory_unknown says why)
    memory_unknown: str = ""

    @property
    def name(self) -> str:
        """"AMD GPU (1002:744c)": the vendor, and the PCI ids when the device's was read."""
        vendor_id = next(pci for pci, vendor in PCI_VENDORS.items() if vendor == self.vendor)
        return f"{self.vendor} GPU" + (f" ({vendor_id[2:]}:{self.device[2:]})" if self.device else "")

    def as_json(self) -> dict:
        return {"vendor": self.vendor, "card": self.card, "pci_device": self.device or None, "name": self.name,
                "memory_bytes": self.memory, "memory_unknown": self.memory_unknown or None}


@dataclass(frozen=True)
class Server:
    """A local model server, as its model list showed it."""

    url: str
    state: str  # SERVING (it listed its models), DOWN (nothing listens), UNKNOWN (why says why)
    models: tuple[str, ...] = ()  # what it lists: untrusted text, fold it before showing it
    why: str = ""
    sizes: Mapping[str, int] = field(default_factory=dict)  # model -> bytes on disk, as Ollama's list gives them
    # Ollama: the models it has loaded now, each with the tokens of context it gives it (/api/ps);
    # None when not asked (another runtime, a server that lists nothing) or its answer could not be
    # read (loaded_why says why)
    loaded: Mapping[str, int] | None = None
    loaded_why: str = ""

    @property
    def address(self) -> str:
        return urlsplit(self.url).netloc

    def lists(self, model: str) -> bool:
        """Whether the server lists `model` (a name without a tag is its ":latest", as Ollama names it)."""
        return self.state == SERVING and (model in self.models or f"{model}:latest" in self.models)

    def size(self, model: str) -> int | None:
        """The bytes on disk the server gives `model` (Ollama's model list does), or None."""
        if not self.lists(model):
            return None
        return self.sizes.get(model, self.sizes.get(f"{model}:latest"))

    def as_json(self) -> dict:
        return {"url": self.url, "state": self.state, "models": list(self.models), "why": self.why or None,
                "sizes": dict(self.sizes), "loaded": dict(self.loaded) if self.loaded is not None else None,
                "loaded_why": self.loaded_why or None}


@dataclass(frozen=True)
class Runtime:
    """One local model runtime: its program on PATH, and its server when it has one to ask."""

    name: str  # OLLAMA, MLX, LLAMA_CPP or LM_STUDIO
    program_name: str = ""  # the program looked for on PATH ("" for none)
    program: str | None = None  # where it is
    importable: bool | None = None  # MLX: whether this Python has the mlx_lm package (None: not asked)
    server: Server | None = None

    @property
    def label(self) -> str:
        return RUNTIME_NAMES[self.name]

    @property
    def installed(self) -> bool:
        return self.program is not None or bool(self.importable)

    def as_json(self) -> dict:
        return {
            "name": self.name, "program_name": self.program_name or None, "program": self.program,
            "importable": self.importable, "server": self.server.as_json() if self.server else None,
        }


@dataclass(frozen=True)
class Machine:
    os: str  # "macOS", "Linux" (WSL too), "Windows", or the platform's own word
    arch: str
    wsl: Fact[bool]
    chip: Fact[str]  # macOS only
    apple_silicon: Fact[bool]
    memory: Fact[int]  # total, in bytes
    gpus: Fact[tuple[Gpu, ...]]  # NVIDIA GPUs; () when none was found, and gpu_note says why
    gpu_note: str = ""
    runtimes: tuple[Runtime, ...] = ()  # empty when they were not probed
    described: bool = False  # True: given by the player (described()), not probed: another machine, perhaps
    # AMD and Intel GPUs (Linux only); () when none was found or looked for, and other_gpu_note says which
    other_gpus: Fact[tuple[OtherGpu, ...]] = Fact(())
    other_gpu_note: str = ""

    def runtime(self, name: str) -> Runtime | None:
        return next((r for r in self.runtimes if r.name == name), None)

    def as_json(self) -> dict:
        return {
            "described": self.described, "os": self.os, "arch": self.arch, "wsl": self.wsl.as_json(),
            "chip": self.chip.as_json(), "apple_silicon": self.apple_silicon.as_json(),
            "memory_bytes": self.memory.as_json(), "nvidia_gpus": {**self.gpus.as_json(), "note": self.gpu_note or None},
            "other_gpus": {**self.other_gpus.as_json(), "note": self.other_gpu_note or None},
            "runtimes": [r.as_json() for r in self.runtimes],
        }


DESCRIBED_GPU = "NVIDIA GPU"  # a described machine's GPU: its memory is all flightdeck is told


def described(memory: int, *, apple: bool = False, gpu: int = 0) -> Machine:
    """A machine the player describes instead of this one (`flightdeck models --memory`): its
    memory in bytes, unified on Apple Silicon (`apple`), and an NVIDIA GPU's memory (`gpu`; 0:
    none). Nothing is probed, so it has no runtimes: what they serve is only this machine's to say."""
    if memory <= 0 or gpu < 0 or (apple and gpu):
        raise ValueError("a described machine has memory above 0, and an NVIDIA GPU (0 or more) only if not Apple Silicon")
    return Machine(
        os="macOS" if apple else "not described", arch="arm64" if apple else "not described", wsl=Fact(False),
        chip=Fact(None, "not described"), apple_silicon=Fact(apple), memory=Fact(memory),
        gpus=Fact((Gpu(DESCRIBED_GPU, gpu),) if gpu else ()), gpu_note="" if gpu else "none described", described=True,
        other_gpu_note="none described",
    )


# ---------------------------------------------------------------------- probing


def probe(host: Host | None = None, *, runtimes: bool = True, servers: Mapping[str, str] = SERVERS,
          http_timeout: float = HTTP_TIMEOUT) -> Machine:
    """This machine's facts (`host`: RealHost() by default). `runtimes=False` skips the
    runtimes (no program lookups for them, no HTTP). `servers` maps OLLAMA, MLX and LM_STUDIO
    to their model-list URLs, each of which must be on 127.0.0.1 (ValueError otherwise)."""
    host = host if host is not None else RealHost()
    if runtimes:
        for url in servers.values():
            local_only(url)
    os_name = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}.get(host.system, host.system or "unknown")
    wsl = _wsl(host) if os_name == "Linux" else Fact(False)
    chip = _chip(host) if os_name == "macOS" else Fact(None, "the chip is read on macOS only")
    gpus, note = _gpus(host)
    if os_name == "Linux":
        other, other_note = _other_gpus(host)
    else:
        other, other_note = Fact(()), f"AMD and Intel GPUs are looked for on Linux only, not on {os_name}"
    found = ()
    if runtimes:
        found = (
            Runtime(OLLAMA, "ollama", host.which("ollama"), server=_loaded(host, _server(host, servers[OLLAMA], _ollama_models,
                                                                                    http_timeout), http_timeout)),
            Runtime(MLX, "mlx_lm.server", host.which("mlx_lm.server"), importable=host.importable("mlx_lm"),
                    server=_server(host, servers[MLX], _listed, http_timeout)),
            Runtime(LLAMA_CPP, "llama-server", host.which("llama-server")),
            Runtime(LM_STUDIO, server=_server(host, servers[LM_STUDIO], _listed, http_timeout)),
        )
    return Machine(
        os=os_name, arch=host.arch or "unknown", wsl=wsl, chip=chip,
        apple_silicon=_apple_silicon(os_name, host.arch, chip), memory=_memory(host, os_name),
        gpus=gpus, gpu_note=note, runtimes=found, other_gpus=other, other_gpu_note=other_note,
    )


def local_only(url: str) -> None:
    """ValueError unless `url` is plain http on 127.0.0.1: the probes contact nothing else
    (not even "localhost", which a hosts file can point anywhere)."""
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != LOCAL_HOST or parts.username is not None:
        raise ValueError(f"the model runtime probes contact only http://{LOCAL_HOST}, not {url!r}")


def _output(host: Host, program: str, args: Sequence[str], timeout: float) -> str:
    path = host.which(program)
    if path is None:
        raise ProbeError(f"{program} is not on PATH")
    return host.run([path, *args], timeout)


def _chip(host: Host) -> Fact[str]:
    try:
        text = _output(host, "sysctl", ["-n", "machdep.cpu.brand_string"], COMMAND_TIMEOUT).strip()
    except ProbeError as exc:
        return Fact(None, str(exc))
    if not text or len(text) > MAX_NAME or not text.isprintable():
        return Fact(None, "sysctl machdep.cpu.brand_string printed something that is not a chip's name")
    return Fact(text)


def _apple_silicon(os_name: str, arch: str, chip: Fact[str]) -> Fact[bool]:
    """Apple Silicon: a Mac whose chip is Apple's, or whose Python runs on arm64 (every arm64
    Mac is Apple Silicon). An x86_64 Python with no chip name may be running under Rosetta."""
    if os_name != "macOS":
        return Fact(False)
    if arch == "arm64" or (chip.value is not None and chip.value.startswith("Apple ")):
        return Fact(True)
    if chip.value is not None:
        return Fact(False)
    return Fact(None, f"the chip is unknown ({chip.unknown}), and this {arch or 'unknown'} Python may run under Rosetta")


def _memory(host: Host, os_name: str) -> Fact[int]:
    if os_name == "macOS":
        try:
            text = _output(host, "sysctl", ["-n", "hw.memsize"], COMMAND_TIMEOUT).strip()
        except ProbeError as exc:
            return Fact(None, str(exc))
        if not _DIGITS.fullmatch(text) or not 0 < int(text) < MAX_MEMORY:
            return Fact(None, "sysctl hw.memsize printed something that is not a number of bytes")
        return Fact(int(text))
    if os_name == "Linux":
        try:
            text = host.read("/proc/meminfo")
        except OSError as exc:
            return Fact(None, f"/proc/meminfo cannot be read ({exc.strerror or type(exc).__name__})")
        found = _MEMTOTAL.findall(text)
        if len(found) != 1 or not 0 < int(found[0]) * 1024 < MAX_MEMORY:
            return Fact(None, "/proc/meminfo has no MemTotal line in kB that flightdeck can read")
        return Fact(int(found[0]) * 1024)
    return Fact(None, f"total memory is read on macOS and Linux (WSL counts as Linux), not on {os_name}")


def _wsl(host: Host) -> Fact[bool]:
    """Linux under WSL, as its kernel names itself ("...-microsoft-standard-WSL2")."""
    try:
        text = host.read("/proc/sys/kernel/osrelease").lower()
    except OSError as exc:
        return Fact(None, f"/proc/sys/kernel/osrelease cannot be read ({exc.strerror or type(exc).__name__})")
    return Fact("microsoft" in text or "wsl" in text)


def _gpus(host: Host) -> tuple[Fact[tuple[Gpu, ...]], str]:
    """The NVIDIA GPUs nvidia-smi lists, with their memory; (Fact(()), why) when none was found."""
    path = host.which("nvidia-smi")
    if path is None:
        return Fact(()), "nvidia-smi is not on PATH"
    try:
        text = host.run([path, *NVIDIA_QUERY], GPU_TIMEOUT)
    except ProbeError as exc:
        return Fact(None, str(exc)), ""
    gpus = []
    for line in text.splitlines():
        if not line.strip():
            continue
        name, comma, mib = (part.strip() for part in line.rpartition(","))
        if not comma or not name or len(name) > MAX_NAME or not name.isprintable():
            return Fact(None, "nvidia-smi printed a line that is not a GPU's name and memory"), ""
        if not _DIGITS.fullmatch(mib) or not 0 < int(mib) * MIB < MAX_MEMORY:
            return Fact(None, "nvidia-smi gave no memory size in MiB for a GPU"), ""
        gpus.append(Gpu(name, int(mib) * MIB))
    if not gpus:
        return Fact(()), "nvidia-smi lists no GPU"
    return Fact(tuple(gpus)), ""


def _other_gpus(host: Host) -> tuple[Fact[tuple[OtherGpu, ...]], str]:
    """The AMD and Intel GPUs of a Linux machine; (Fact(()), why) when none was found. Read
    only: each /sys/class/drm/cardN's PCI vendor and device ids and, for an AMD card, the
    memory its amdgpu driver names there; then rocm-smi, only when it is on PATH and an AMD
    card's memory is still unknown (or no card was found at all: a container can hide /sys)."""
    cards: list[OtherGpu] = []
    for number in range(DRM_CARDS):
        try:
            vendor = PCI_VENDORS.get(host.read(DRM_FILE.format(card=number, name="vendor")).strip().lower())
        except OSError:
            continue  # no such card
        if vendor is None:
            continue  # another vendor's: an NVIDIA GPU (nvidia-smi's to list), a virtual display
        try:
            device = host.read(DRM_FILE.format(card=number, name="device")).strip().lower()
        except OSError:
            device = ""
        device = device if _PCI_ID.fullmatch(device) else ""
        if vendor == INTEL:
            cards.append(OtherGpu(INTEL, f"card{number}", device,
                                  memory_unknown="flightdeck reads no memory size for an Intel GPU"))
            continue
        path = DRM_FILE.format(card=number, name="mem_info_vram_total")
        try:
            text = host.read(path).strip()
        except OSError as exc:
            cards.append(OtherGpu(AMD, f"card{number}", device,
                                  memory_unknown=f"{path} cannot be read ({exc.strerror or type(exc).__name__})"))
            continue
        if _DIGITS.fullmatch(text) and 0 < int(text) < MAX_MEMORY:
            cards.append(OtherGpu(AMD, f"card{number}", device, int(text)))
        else:
            cards.append(OtherGpu(AMD, f"card{number}", device, memory_unknown=f"{path} holds no number of bytes"))
    rocm = host.which("rocm-smi")
    if rocm is not None and (not cards or any(c.vendor == AMD and c.memory is None for c in cards)):
        cards, failed = _with_rocm(host, rocm, cards)
        if not cards and failed:  # /sys showed no card, and rocm-smi, which is here, could not be read
            return Fact(None, failed), ""
    if not cards:
        looked = f"no AMD or Intel GPU among /sys/class/drm/card0 to card{DRM_CARDS - 1}"
        return Fact(()), looked + ("" if rocm is None else ", and rocm-smi lists none")
    return Fact(tuple(cards)), ""


def _with_rocm(host: Host, rocm: str, cards: list[OtherGpu]) -> tuple[list[OtherGpu], str]:
    """(`cards` with what rocm-smi says of AMD GPUs' memory, why its answer could not be read
    or ""): an AMD card whose memory is unknown gets it, and a card /sys did not show is added.
    An answer that cannot be read changes no number: each AMD card still without memory says why."""
    from dataclasses import replace

    why, rows = "", {}
    try:
        text = host.run([rocm, *ROCM_QUERY], GPU_TIMEOUT)
    except ProbeError as exc:
        why = str(exc)
    else:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        found = [_ROCM_ROW.fullmatch(line.replace(" ", "")) for line in lines[1:]]
        if not lines or not lines[0].lower().startswith("device,") or not all(found):
            why = "rocm-smi printed something that is not its table of GPU memory"
        else:
            rows = {f"card{int(m.group(1))}": int(m.group(2)) for m in found if m is not None}
            if not all(0 < size < MAX_MEMORY for size in rows.values()):
                why, rows = "rocm-smi gave no memory size in bytes for a GPU", {}
    out = []
    for card in cards:
        if card.vendor == AMD and card.memory is None:
            if card.card in rows:
                card = replace(card, memory=rows[card.card], memory_unknown="")
            else:
                said = why or f"rocm-smi lists no {card.card}"
                card = replace(card, memory_unknown=f"{card.memory_unknown}; {said}")
        out.append(card)
    known = {card.card for card in cards}
    out += [OtherGpu(AMD, name, memory=size) for name, size in sorted(rows.items()) if name not in known]
    return out, why


Listing = tuple[list[str], dict[str, int]]  # a server's model names, and the sizes it gives (bytes)


def _server(host: Host, url: str, parse: Callable[[object], Listing | None], timeout: float) -> Server:
    local_only(url)
    try:
        status, body = host.get(url, timeout)
    except Refused as exc:
        return Server(url, DOWN, why=str(exc))
    except ProbeError as exc:
        return Server(url, UNKNOWN, why=str(exc))
    if status != 200:
        return Server(url, UNKNOWN, why=f"something answers there with HTTP {status}, not a model list")
    try:
        listing = parse(json.loads(body))
    except (ValueError, RecursionError):
        listing = None
    if listing is None:
        return Server(url, UNKNOWN, why="something answers there, but not with a model list flightdeck can read")
    names, sizes = listing
    return Server(url, SERVING, models=tuple(names), sizes=sizes)


def _loaded(host: Host, server: Server, timeout: float) -> Server:
    """An Ollama server that listed its models, with the models it has loaded and the context it
    gives each (/api/ps, beside /api/tags: ollama_context.py); any other, as it is."""
    from dataclasses import replace

    from .ollama_context import PS_PATH, loaded_contexts

    if server.state != SERVING:
        return server
    url = server.url.removesuffix("/api/tags") + PS_PATH
    local_only(url)
    try:
        status, body = host.get(url, timeout)
    except ProbeError as exc:  # Refused too: it answered /api/tags a moment ago
        return replace(server, loaded_why=f"{PS_PATH}: {exc}")
    if status != 200:
        return replace(server, loaded_why=f"{PS_PATH} answered HTTP {status}")
    try:
        loaded = loaded_contexts(json.loads(body))
    except (ValueError, RecursionError):
        loaded = None
    if loaded is None:
        return replace(server, loaded_why=f"{PS_PATH} answered with something that is not Ollama's list of loaded models")
    return replace(server, loaded=loaded)


def _ollama_models(body: object) -> Listing | None:
    """The names in Ollama's /api/tags answer ({"models": [{"name": ..., "size": ...}, ...]}),
    and the size on disk it gives each (a size that is not a whole number of bytes is left
    out), or None when `body` is not one."""
    items = body.get("models") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return None
    names = [item.get("name") for item in items if isinstance(item, dict)]
    if len(names) != len(items) or not all(isinstance(name, str) and name for name in names):
        return None
    sizes = {item["name"]: item["size"] for item in items if type(item.get("size")) is int and 0 < item["size"] < MAX_MEMORY}
    return names, sizes


def _listed(body: object) -> Listing | None:
    """The ids in an OpenAI-style model list (it gives no sizes), or None."""
    from .apicheck import listed_models

    names = listed_models(body)
    return None if names is None else (names, {})


# ---------------------------------------------------------------------- this machine


class RealHost:
    """This machine. Programs come from the absolute folders of `environ`'s PATH."""

    def __init__(self, environ: Mapping[str, str] = os.environ) -> None:
        self.environ = environ
        self.system = platform.system()
        self.arch = platform.machine()

    def which(self, program: str) -> str | None:
        from .agent.workspace import absolute_path

        path = absolute_path(self.environ.get("PATH", os.defpath))
        found = shutil.which(program, path=path) if path else None
        if found is None and program in SYSTEM_PROGRAMS.get(self.system, {}):
            found = shutil.which(program, path=SYSTEM_PROGRAMS[self.system][program])  # a PATH that left it out
        return str(Path(found).absolute()) if found else None

    def run(self, argv: Sequence[str], timeout: float) -> str:
        name = os.path.basename(argv[0])
        env = {**self.environ, "LC_ALL": "C"}  # numbers and names as the program prints them by default
        try:
            done = subprocess.run(list(argv), capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env, check=False)
        except subprocess.TimeoutExpired:
            raise ProbeError(f"{name} gave no answer within {timeout:g} s") from None
        except OSError as exc:
            raise ProbeError(f"{name} cannot be run ({exc.strerror or type(exc).__name__})") from None
        if done.returncode != 0:
            raise ProbeError(f"{name} failed (exit status {done.returncode})")
        return done.stdout.decode("utf-8", "replace")

    def get(self, url: str, timeout: float) -> tuple[int, bytes]:
        return http_get(url, timeout)

    def read(self, path: str) -> str:
        with open(path, "rb") as handle:
            return handle.read(MAX_FILE).decode("utf-8", "replace")

    def importable(self, module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False


def http_get(url: str, timeout: float) -> tuple[int, bytes]:
    """GET a URL on 127.0.0.1 (ValueError for any other): (status, body), the whole answer
    within about `timeout` seconds and MAX_BODY bytes. No proxy from the environment, no
    redirect: the request goes to 127.0.0.1 and nowhere else."""
    import httpx

    local_only(url)
    begun = time.monotonic()
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY:
                        raise ProbeError(f"its answer is longer than {MAX_BODY // MIB} MB")
                    if time.monotonic() - begun > timeout:
                        raise ProbeError(f"its answer took longer than {timeout:g} s")
                return response.status_code, bytes(body)
    except httpx.ConnectError:
        raise Refused("nothing is listening there") from None
    except httpx.TimeoutException:
        raise ProbeError(f"no answer within {timeout:g} s") from None
    except httpx.HTTPError as exc:
        raise ProbeError(f"the request failed ({type(exc).__name__})") from None


# ---------------------------------------------------------------------- in short


def gib(n: int) -> str:
    """Bytes as GiB, one decimal at most: "36 GiB", "5.5 GiB"."""
    text = f"{n / GIB:.1f}"
    return f"{text.removesuffix('.0')} GiB"


def summary(machine: Machine) -> str:
    """The machine in one line: chip or system, memory, GPUs."""
    from .text import untrusted

    if machine.os == "macOS":
        what = untrusted(machine.chip.value, one_line=True) if machine.chip.value else f"macOS on {machine.arch}"
        if machine.apple_silicon.value:
            what += " (Apple Silicon)"
    else:
        what = f"{machine.os}{' (WSL)' if machine.wsl.value else ''} on {machine.arch}"
    kind = "unified memory" if machine.apple_silicon.value else "memory"
    memory = f"{gib(machine.memory.value)} of {kind}" if machine.memory.value else "memory unknown"
    parts = [what, memory]
    if machine.gpus.value:
        parts += [f"{untrusted(g.name, one_line=True)} ({gib(g.memory)})" for g in machine.gpus.value]
    elif machine.gpus.value is None:
        parts.append("NVIDIA GPUs unknown")
    elif machine.os != "macOS":
        parts.append("no NVIDIA GPU found")
    if machine.other_gpus.value:
        parts.append(f"{other_gpus_text(machine.other_gpus.value)} (flightdeck has no results for "
                     f"{'it' if len(machine.other_gpus.value) == 1 else 'them'} yet)")
    elif machine.other_gpus.value is None:
        parts.append("AMD GPUs unknown")
    return ", ".join(parts)


def other_gpus_text(gpus: Sequence[OtherGpu]) -> str:
    """AMD and Intel GPUs in a few words: "AMD GPU (1002:744c) with 16 GiB and Intel GPU (8086:56a0), memory not read"."""
    said = [f"{g.name} with {gib(g.memory)}" if g.memory is not None else f"{g.name}, memory not read" for g in gpus]
    return said[0] if len(said) == 1 else ", ".join(said[:-1]) + " and " + said[-1]


def doctor_line(environ: Mapping[str, str] = os.environ, host: Host | None = None, machine: Machine | None = None) -> str:
    """doctor's line about this machine (`machine` as probed, else probed on `host`, by default
    RealHost(environ)): the machine in short. No runtime or server is asked."""
    if machine is None:
        machine = probe(host if host is not None else RealHost(environ), runtimes=False)
    return f"{summary(machine)}; `flightdeck models` suggests local models that fit"
