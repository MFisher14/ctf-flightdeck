"""Deterministic, inert Docker plans for Ghidra, angr, and RetDec.

The builders return argv tuples and generated source strings.  They never
write those strings, import a decompiler, spawn a process, or inspect an
artifact.  Every plan declares a networkless, capability-dropped Docker
environment; callers remain responsible for materializing and running it via
``tools/sandbox.py``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Mapping, Sequence


MAX_TIMEOUT = 1800
_FORMATS = {"auto", "elf", "pe", "macho", "raw"}
_ARCHES = {"x86", "amd64", "arm", "aarch64", "mips", "ppc", "riscv"}
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_PROJECT = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


@dataclass(frozen=True)
class ArtifactProfile:
    format: str = "auto"
    architecture: str | None = None
    bits: int | None = None
    endian: str = "little"
    base_address: int | None = None
    entrypoint: int | None = None

    @classmethod
    def from_mapping(cls, raw: "ArtifactProfile | Mapping[str, object] | None") -> "ArtifactProfile":
        if isinstance(raw, cls):
            raw = asdict(raw)
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise TypeError("artifact profile must be a mapping")
        allowed = {"format", "architecture", "bits", "endian", "base_address", "entrypoint"}
        unknown = [key for key in raw if key not in allowed]
        if unknown:
            raise ValueError(f"unknown profile key(s): {sorted(map(repr, unknown))}")
        format_name = raw.get("format", "auto")
        architecture = raw.get("architecture")
        bits = raw.get("bits")
        endian = raw.get("endian", "little")
        base = _optional_address(raw.get("base_address"), "base_address")
        entrypoint = _optional_address(raw.get("entrypoint"), "entrypoint")
        if format_name not in _FORMATS:
            raise ValueError("unsupported artifact format")
        if architecture is not None and architecture not in _ARCHES:
            raise ValueError("unsupported architecture")
        if bits is not None and bits not in {32, 64}:
            raise ValueError("bits must be 32 or 64")
        expected_bits = {
            "x86": {32}, "amd64": {64}, "arm": {32}, "aarch64": {64},
            "mips": {32}, "ppc": {32}, "riscv": {32, 64},
        }
        if architecture is not None and bits is not None and bits not in expected_bits[architecture]:
            raise ValueError("architecture and bit width are inconsistent")
        if endian not in {"little", "big"}:
            raise ValueError("endian must be little or big")
        if format_name == "raw":
            if architecture is None or bits is None or base is None or entrypoint is None:
                raise ValueError("raw artifacts require architecture, bits, base_address, and entrypoint")
            if entrypoint < base:
                raise ValueError("raw entrypoint must not precede base_address")
        elif base is not None or entrypoint is not None:
            raise ValueError("base_address/entrypoint are accepted only for raw artifacts")
        return cls(str(format_name), architecture, bits, str(endian), base, entrypoint)


@dataclass(frozen=True)
class DecompilerPlan:
    engine: str
    image: str
    argv: tuple[str, ...]
    generated_files: tuple[tuple[str, str], ...]
    expected_outputs: tuple[str, ...]
    timeout_seconds: int
    network: str = "none"
    read_only_root: bool = True
    drop_capabilities: tuple[str, ...] = ("ALL",)

    def to_dict(self) -> dict:
        return asdict(self)


def _name(value: str, field: str) -> str:
    if (not isinstance(value, str) or not _SAFE_NAME.fullmatch(value)
            or value in {".", ".."} or ".." in value):
        raise ValueError(f"unsafe {field} basename")
    return value


def _timeout(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_TIMEOUT:
        raise ValueError("timeout_seconds must be in 1..1800")
    return value


def _optional_address(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        if not re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)", value):
            raise ValueError(f"{field} must be a literal address")
        value = int(value, 16 if value.lower().startswith("0x") else 10)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError(f"{field} must be an unsigned 64-bit address")
    return value


def ghidra_export_source() -> str:
    """Fixed post-script source; Ghidra receives output path as one argv item."""
    return '''# Source-only plan; execute solely in the networkless Docker image.
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import FileWriter
import json

args = getScriptArgs()
if len(args) != 1:
    raise ValueError("expected one output path")
interface = DecompInterface()
interface.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
rows = []
functions = currentProgram.getFunctionManager().getFunctions(True)
total_text = 0
while functions.hasNext() and len(rows) < 10000 and total_text < 67108864:
    function = functions.next()
    result = interface.decompileFunction(function, 30, monitor)
    decompiled = result.getDecompiledFunction().getC() if result.decompileCompleted() else None
    name = str(function.getName())[:4096]
    signature = str(function.getSignature())[:4096]
    remaining = max(0, 67108864 - total_text - len(name) - len(signature))
    if decompiled is not None:
        decompiled = decompiled[:min(1048576, remaining)]
    total_text += len(name) + len(signature) + (len(decompiled) if decompiled is not None else 0)
    rows.append({
        "address": str(function.getEntryPoint()),
        "name": name,
        "signature": signature,
        "decompiled": decompiled,
    })
writer = FileWriter(args[0])
try:
    writer.write(json.dumps({"functions": rows}, sort_keys=True))
finally:
    writer.close()
'''


_GHIDRA_LANGUAGE = {
    ("x86", 32, "little"): "x86:LE:32:default",
    ("amd64", 64, "little"): "x86:LE:64:default",
    ("arm", 32, "little"): "ARM:LE:32:v8",
    ("aarch64", 64, "little"): "AARCH64:LE:64:v8A",
    ("mips", 32, "little"): "MIPS:LE:32:default",
    ("mips", 32, "big"): "MIPS:BE:32:default",
    ("ppc", 32, "big"): "PowerPC:BE:32:default",
}


def build_ghidra_plan(
    input_name: str,
    profile: ArtifactProfile | Mapping[str, object] | None = None,
    *,
    project_name: str = "r5d_analysis",
    output_name: str = "r5d_ghidra.json",
    timeout_seconds: int = 900,
) -> DecompilerPlan:
    source = _name(input_name, "input")
    output = _name(output_name, "output")
    value = ArtifactProfile.from_mapping(profile)
    if not isinstance(project_name, str) or not _SAFE_PROJECT.fullmatch(project_name):
        raise ValueError("unsafe Ghidra project name")
    argv = [
        "/opt/ghidra/support/analyzeHeadless", "/tmp/r5d-ghidra", project_name,
        "-import", f"/work/{source}", "-scriptPath", "/plan",
        "-postScript", "r5d_ghidra_export.py", f"/out/{output}", "-deleteProject",
    ]
    if value.format == "raw":
        language = _GHIDRA_LANGUAGE.get((value.architecture, value.bits, value.endian))
        if language is None:
            raise ValueError("no deterministic Ghidra language id for raw profile")
        argv[5:5] = [
            "-loader", "BinaryLoader", "-loader-baseAddr", f"{value.base_address:#x}",
            "-processor", language,
        ]
    return DecompilerPlan(
        engine="ghidra",
        image="docker/pwn",
        argv=tuple(argv),
        generated_files=(("r5d_ghidra_export.py", ghidra_export_source()),),
        expected_outputs=(f"/out/{output}",),
        timeout_seconds=_timeout(timeout_seconds),
    )


def angr_cfg_source(profile: ArtifactProfile | Mapping[str, object] | None = None) -> str:
    """Return a bounded CFG/decompiler-lead exporter for Docker execution."""
    value = ArtifactProfile.from_mapping(profile)
    project_options: dict[str, object] = {"auto_load_libs": False}
    if value.format == "raw":
        arch = {
            "x86": "X86", "amd64": "AMD64", "arm": "ARMEL", "aarch64": "AARCH64",
            "mips": "MIPS32EL" if value.endian == "little" else "MIPS32",
            "ppc": "PPC32", "riscv": "RISCV64" if value.bits == 64 else "RISCV32",
        }.get(value.architecture)
        if arch is None:
            raise ValueError("unsupported angr raw architecture")
        if value.architecture in {"x86", "amd64", "arm", "aarch64", "riscv"} and value.endian != "little":
            raise ValueError("selected angr raw architecture requires little endian")
        project_options["main_opts"] = {
            "backend": "blob", "arch": arch, "base_addr": value.base_address,
            "entry_point": value.entrypoint,
        }
    return f'''#!/usr/bin/env python3
"""Generated plan; execute solely in the networkless Docker image."""
import json
import sys
import angr

if len(sys.argv) != 3:
    raise SystemExit("usage: r5d_angr_cfg.py INPUT OUTPUT")
project = angr.Project(sys.argv[1], **{project_options!r})
cfg = project.analyses.CFGFast(normalize=True, data_references=True)
functions = []
for address in sorted(cfg.kb.functions)[:10000]:
    function = cfg.kb.functions[address]
    blocks = []
    for block in function.blocks:
        blocks.append({{"address": block.addr, "size": block.size}})
        if len(blocks) >= 4096:
            break
    blocks.sort(key=lambda item: item["address"])
    functions.append({{
        "address": address,
        "name": function.name,
        "returning": function.returning,
        "blocks": blocks,
    }})
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump({{"functions": functions}}, handle, sort_keys=True)
'''


def build_angr_plan(
    input_name: str,
    profile: ArtifactProfile | Mapping[str, object] | None = None,
    *,
    output_name: str = "r5d_angr.json",
    timeout_seconds: int = 600,
) -> DecompilerPlan:
    source, output = _name(input_name, "input"), _name(output_name, "output")
    value = ArtifactProfile.from_mapping(profile)
    script = angr_cfg_source(value)
    return DecompilerPlan(
        engine="angr",
        image="docker/pwn",
        argv=("python3", "/plan/r5d_angr_cfg.py", f"/work/{source}", f"/out/{output}"),
        generated_files=(("r5d_angr_cfg.py", script),),
        expected_outputs=(f"/out/{output}",),
        timeout_seconds=_timeout(timeout_seconds),
    )


def build_retdec_plan(
    input_name: str,
    profile: ArtifactProfile | Mapping[str, object] | None = None,
    *,
    output_name: str = "r5d_retdec.c",
    timeout_seconds: int = 900,
) -> DecompilerPlan:
    source, output = _name(input_name, "input"), _name(output_name, "output")
    value = ArtifactProfile.from_mapping(profile)
    argv = ["retdec-decompiler", "--cleanup", "--output", f"/out/{output}"]
    if value.architecture is not None:
        argv.extend(("--arch", value.architecture))
    if value.format == "raw":
        argv.extend(("--mode", "raw", "--raw-section-vma", f"{value.base_address:#x}"))
    argv.append(f"/work/{source}")
    return DecompilerPlan(
        engine="retdec",
        image="docker/pwn",
        argv=tuple(argv),
        generated_files=(),
        expected_outputs=(f"/out/{output}",),
        timeout_seconds=_timeout(timeout_seconds),
    )


def build_decompiler_matrix(
    input_name: str,
    profile: ArtifactProfile | Mapping[str, object] | None = None,
    *,
    engines: Sequence[str] = ("ghidra", "angr", "retdec"),
) -> tuple[DecompilerPlan, ...]:
    """Build selected plans in canonical engine order, independent of input order."""
    if not isinstance(engines, Sequence) or isinstance(engines, (str, bytes)):
        raise TypeError("engines must be a sequence")
    if not engines or any(not isinstance(engine, str) for engine in engines):
        raise ValueError("engines must contain supported names")
    selected = set(engines)
    if len(selected) != len(engines) or not selected <= {"ghidra", "angr", "retdec"}:
        raise ValueError("engines must be distinct supported names")
    value = ArtifactProfile.from_mapping(profile)
    builders = {
        "ghidra": build_ghidra_plan,
        "angr": build_angr_plan,
        "retdec": build_retdec_plan,
    }
    return tuple(builders[name](input_name, value) for name in ("ghidra", "angr", "retdec") if name in selected)


def render_plan_manifest(plans: Sequence[DecompilerPlan]) -> str:
    if not isinstance(plans, Sequence) or isinstance(plans, (str, bytes)):
        raise TypeError("plans must be a sequence")
    if any(not isinstance(plan, DecompilerPlan) for plan in plans):
        raise TypeError("plans must contain DecompilerPlan values")
    return json.dumps([plan.to_dict() for plan in plans], sort_keys=True, separators=(",", ":"))


__all__ = [
    "ArtifactProfile", "DecompilerPlan", "ghidra_export_source", "angr_cfg_source",
    "build_ghidra_plan", "build_angr_plan", "build_retdec_plan",
    "build_decompiler_matrix", "render_plan_manifest",
]
