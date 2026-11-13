"""Generate inert Qiling and Unicorn firmware-emulation plans.

The builders in this module only return validated manifests, argv tuples, and
generated Python source. They do not read firmware, import an emulator, launch
a process, or execute artifact-derived code. Generated plans declare a
networkless, read-only-root, capability-dropped Docker environment and require
review before sandbox execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Mapping, Sequence


MAX_REGIONS = 32
MAX_REGION_SIZE = 256 << 20
MAX_TOTAL_MEMORY = 512 << 20
MAX_FIRMWARE_BYTES = 256 << 20
MAX_HOOKS = 256
MAX_INSTRUCTIONS = 10_000_000
MAX_TIMEOUT = 1800
MAX_SOURCE_CHARS = 1 << 20

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LITERAL_ADDRESS = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)\Z")
_ARCHES = {
    "x86": 32,
    "amd64": 64,
    "arm": 32,
    "aarch64": 64,
    "mips": 32,
    "mips64": 64,
    "riscv32": 32,
    "riscv64": 64,
}
_FORMATS = {"elf", "raw"}
_SYSTEMS = {"linux", "baremetal", "freertos", "unknown"}
_SPEC_KEYS = {
    "input_name", "format", "architecture", "endian", "operating_system",
    "instruction_set", "rootfs_name", "base_address", "entrypoint", "memory_regions",
    "hook_addresses", "stop_addresses", "max_instructions", "timeout_seconds",
}


@dataclass(frozen=True)
class MemoryRegion:
    address: int
    size: int
    permissions: str = "rwx"

    @classmethod
    def from_mapping(cls, raw: "MemoryRegion | Mapping[str, object]") -> "MemoryRegion":
        if isinstance(raw, cls):
            raw = asdict(raw)
        if not isinstance(raw, Mapping):
            raise ValueError("memory region must be a mapping")
        unknown = sorted(str(key) for key in raw if key not in {"address", "size", "permissions"})
        if unknown:
            raise ValueError(f"unknown memory-region key(s): {unknown!r}")
        address = _address(raw.get("address"), "memory-region address")
        size = _bounded_int(raw.get("size"), "memory-region size", 0x1000, MAX_REGION_SIZE)
        permissions = raw.get("permissions", "rwx")
        if (not isinstance(permissions, str) or not permissions
                or any(char not in "rwx" for char in permissions)
                or len(set(permissions)) != len(permissions)):
            raise ValueError("memory-region permissions must be a distinct subset of rwx")
        if address % 0x1000 or size % 0x1000:
            raise ValueError("memory regions must be page aligned")
        if address + size > 1 << 64:
            raise ValueError("memory region exceeds the unsigned 64-bit address space")
        return cls(address, size, "".join(char for char in "rwx" if char in permissions))


@dataclass(frozen=True)
class FirmwareSpec:
    input_name: str
    format: str
    architecture: str
    endian: str
    instruction_set: str
    operating_system: str
    rootfs_name: str | None
    base_address: int | None
    entrypoint: int | None
    memory_regions: tuple[MemoryRegion, ...]
    hook_addresses: tuple[int, ...] = ()
    stop_addresses: tuple[int, ...] = ()
    max_instructions: int = 500_000
    timeout_seconds: int = 600

    @classmethod
    def from_mapping(cls, raw: "FirmwareSpec | Mapping[str, object]") -> "FirmwareSpec":
        if isinstance(raw, cls):
            raw = asdict(raw)
        if not isinstance(raw, Mapping):
            raise ValueError("firmware specification must be a mapping")
        unknown = sorted(str(key) for key in raw if key not in _SPEC_KEYS)
        if unknown:
            raise ValueError(f"unknown firmware specification key(s): {unknown!r}")
        input_name = _name(raw.get("input_name", "firmware.bin"), "input")
        format_name = raw.get("format")
        if not isinstance(format_name, str) or format_name not in _FORMATS:
            raise ValueError("firmware format must be elf or raw")
        architecture = raw.get("architecture")
        if not isinstance(architecture, str) or architecture not in _ARCHES:
            raise ValueError("unsupported firmware architecture")
        endian = raw.get("endian", "little")
        if not isinstance(endian, str) or endian not in {"little", "big"}:
            raise ValueError("endian must be little or big")
        if architecture in {"x86", "amd64"} and endian != "little":
            raise ValueError("x86 firmware must use little endian")
        instruction_set_raw = raw.get("instruction_set")
        if format_name == "raw" and architecture == "arm":
            if instruction_set_raw not in {"arm", "thumb", "cortex-m"}:
                raise ValueError("raw ARM firmware requires instruction_set arm, thumb, or cortex-m")
            instruction_set = str(instruction_set_raw)
        elif format_name == "elf":
            if instruction_set_raw not in {None, "auto"}:
                raise ValueError("ELF/Qiling instruction_set must be auto")
            instruction_set = "auto"
        else:
            if instruction_set_raw not in {None, "default"}:
                raise ValueError("instruction_set is supported only for raw ARM firmware")
            instruction_set = "default"
        operating_system = raw.get("operating_system", "unknown")
        if not isinstance(operating_system, str) or operating_system not in _SYSTEMS:
            raise ValueError("unsupported firmware operating system")
        rootfs_raw = raw.get("rootfs_name")
        rootfs = None if rootfs_raw is None else _name(rootfs_raw, "rootfs")
        base = _optional_address(raw.get("base_address"), "base_address")
        entry = _optional_address(raw.get("entrypoint"), "entrypoint")
        if format_name == "raw" and architecture == "arm" and instruction_set in {"thumb", "cortex-m"}:
            entry = None if entry is None else entry & ~1
        regions_raw = raw.get("memory_regions", ())
        if not isinstance(regions_raw, (tuple, list)) or len(regions_raw) > MAX_REGIONS:
            raise ValueError(f"memory_regions must contain at most {MAX_REGIONS} entries")
        regions = tuple(sorted(
            (MemoryRegion.from_mapping(item) for item in regions_raw),
            key=lambda item: item.address,
        ))
        _validate_regions(regions)
        hooks = _addresses(raw.get("hook_addresses", ()), "hook_addresses")
        stops = _addresses(raw.get("stop_addresses", ()), "stop_addresses")
        if format_name == "raw" and architecture == "arm" and instruction_set in {"thumb", "cortex-m"}:
            hooks = tuple(sorted({address & ~1 for address in hooks}))
            stops = tuple(sorted({address & ~1 for address in stops}))
        address_bits = _ARCHES[architecture]
        if address_bits < 64:
            limit = 1 << address_bits
            out_of_range = [a for a in (base, entry, *hooks, *stops) if a is not None and a >= limit]
            out_of_range += [r.address for r in regions if r.address >= limit]
            out_of_range += [r.address + r.size for r in regions if r.address + r.size > limit]
            if out_of_range:
                raise ValueError("address does not fit the selected architecture's address space")
        if format_name == "raw":
            if base is None or entry is None or not regions:
                raise ValueError("raw firmware requires base_address, entrypoint, and memory_regions")
            if entry < base:
                raise ValueError("raw entrypoint must not precede base_address")
            if not any(region.address <= base < region.address + region.size for region in regions):
                raise ValueError("base_address is outside the mapped memory regions")
            if not any(region.address <= entry < region.address + region.size for region in regions):
                raise ValueError("entrypoint is outside the mapped memory regions")
            entry_region = next(
                region for region in regions if region.address <= entry < region.address + region.size
            )
            base_region = next(
                region for region in regions if region.address <= base < region.address + region.size
            )
            if entry_region != base_region:
                raise ValueError("raw entrypoint and base_address must share the loaded image region")
            if "x" not in entry_region.permissions:
                raise ValueError("raw entrypoint must lie in an executable memory region")
            unmapped_controls = [
                address for address in (*hooks, *stops)
                if not any(region.address <= address < region.address + region.size for region in regions)
            ]
            if unmapped_controls:
                raise ValueError("raw hook/stop address is outside the mapped memory regions")
            if rootfs is not None:
                raise ValueError("raw Unicorn firmware does not accept rootfs_name")
        else:
            if base is not None or entry is not None or regions:
                raise ValueError(
                    "ELF firmware derives base/entry/regions from its Qiling loader"
                )
            if operating_system == "linux" and rootfs is None:
                raise ValueError("Linux Qiling plans require rootfs_name")
            if rootfs is None:
                raise ValueError("Qiling ELF plans require rootfs_name")
            if operating_system != "linux":
                raise ValueError("current Qiling ELF plans require operating_system linux")
        return cls(
            input_name=input_name,
            format=str(format_name),
            architecture=str(architecture),
            endian=str(endian),
            instruction_set=instruction_set,
            operating_system=str(operating_system),
            rootfs_name=rootfs,
            base_address=base,
            entrypoint=entry,
            memory_regions=regions,
            hook_addresses=hooks,
            stop_addresses=stops,
            max_instructions=_bounded_int(
                raw.get("max_instructions", 500_000),
                "max_instructions", 1, MAX_INSTRUCTIONS,
            ),
            timeout_seconds=_bounded_int(
                raw.get("timeout_seconds", 600), "timeout_seconds", 1, MAX_TIMEOUT
            ),
        )


@dataclass(frozen=True)
class EmulationPlan:
    engine: str
    image: str
    argv: tuple[str, ...]
    generated_files: tuple[tuple[str, str], ...]
    expected_outputs: tuple[str, ...]
    manifest: str
    timeout_seconds: int
    review_notes: tuple[str, ...]
    runtime_requirements: tuple[str, ...]
    image_build_required: bool
    network: str = "none"
    read_only_root: bool = True
    drop_capabilities: tuple[str, ...] = ("ALL",)
    artifact_execution_expected: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _name(value: object, field: str) -> str:
    if (not isinstance(value, str) or not _SAFE_NAME.fullmatch(value)
            or value in {".", ".."} or ".." in value):
        raise ValueError(f"unsafe {field} basename")
    return value


def _bounded_int(value: object, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer in {minimum}..{maximum}")
    return value


def _address(value: object, field: str) -> int:
    if isinstance(value, str):
        if not _LITERAL_ADDRESS.fullmatch(value):
            raise ValueError(f"{field} must be a literal address")
        value = int(value, 16 if value.lower().startswith("0x") else 10)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError(f"{field} must be an unsigned 64-bit address")
    return value


def _optional_address(value: object, field: str) -> int | None:
    return None if value is None else _address(value, field)


def _addresses(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list)) or len(value) > MAX_HOOKS:
        raise ValueError(f"{field} must contain at most {MAX_HOOKS} addresses")
    return tuple(sorted({_address(item, field) for item in value}))


def _validate_regions(regions: tuple[MemoryRegion, ...]) -> None:
    if sum(region.size for region in regions) > MAX_TOTAL_MEMORY:
        raise ValueError("aggregate mapped memory exceeds the 512 MiB cap")
    previous_end = 0
    for index, region in enumerate(regions):
        if index and region.address < previous_end:
            raise ValueError("memory regions must not overlap")
        previous_end = region.address + region.size


def normalize_spec(spec: FirmwareSpec | Mapping[str, object]) -> FirmwareSpec:
    return FirmwareSpec.from_mapping(spec)


def _manifest_dict(value: FirmwareSpec, engine: str) -> dict[str, object]:
    return {
        "architecture": value.architecture,
        "base_address": value.base_address,
        "endian": value.endian,
        "engine": engine,
        "entrypoint": value.entrypoint,
        "format": value.format,
        "hook_addresses": list(value.hook_addresses),
        "input_name": value.input_name,
        "instruction_set": value.instruction_set,
        "limits": {
            "instructions": value.max_instructions,
            "timeout_seconds": value.timeout_seconds,
        },
        "memory_regions": [asdict(region) for region in value.memory_regions],
        "network": "none",
        "operating_system": value.operating_system,
        "rootfs_name": value.rootfs_name,
        "sandbox_required": True,
        "stop_addresses": list(value.stop_addresses),
    }


def render_spec_manifest(spec: FirmwareSpec | Mapping[str, object], engine: str) -> str:
    value = normalize_spec(spec)
    if engine not in {"qiling", "unicorn"}:
        raise ValueError("engine must be qiling or unicorn")
    return json.dumps(_manifest_dict(value, engine), sort_keys=True, separators=(",", ":"))


def _review_notes(value: FirmwareSpec) -> tuple[str, ...]:
    notes = [
        "Run only through tools/sandbox.py with Docker networking disabled.",
        "Review MMIO/peripheral and syscall assumptions before artifact execution.",
        "Treat emulator output as evidence, not as proof of real-device behavior.",
    ]
    if value.architecture.startswith("mips"):
        notes.append("Confirm MIPS delay-slot and endian assumptions against the saved header/disassembly.")
    if value.operating_system in {"baremetal", "freertos", "unknown"}:
        notes.append("Model unmapped MMIO explicitly; the default plan stops on emulator errors.")
    if value.instruction_set in {"thumb", "cortex-m"}:
        notes.append(
            "Manifest entry/hook/stop addresses are canonical even addresses; the plan sets bit 0 only for emulation start."
        )
    return tuple(notes)


def build_qiling_plan(
    spec: FirmwareSpec | Mapping[str, object],
    *,
    output_name: str = "r5d_qiling_trace.json",
) -> EmulationPlan:
    """Return a Qiling userspace-firmware plan; no emulator is imported."""
    value = normalize_spec(spec)
    if value.format != "elf" or value.rootfs_name is None:
        raise ValueError("Qiling plans require ELF firmware and a rootfs")
    output = _name(output_name, "output")
    arch_tokens = {
        "x86": ("x86",), "amd64": ("x8664", "amd64"),
        "arm": ("arm",), "aarch64": ("arm64", "aarch64"),
        "mips": ("mips",), "mips64": ("mips64",),
        "riscv32": ("riscv",), "riscv64": ("riscv64", "riscv"),
    }[value.architecture]
    endian_tokens = ("el", "little") if value.endian == "little" else ("eb", "big")
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated plan: execute only in the networkless CSCTF Docker sandbox."""',
        "import json",
        "from pathlib import Path",
        "from qiling import Qiling",
        "from qiling.const import QL_VERBOSE",
        f"BINARY = {'/work/' + value.input_name!r}",
        f"ROOTFS = {'/work/' + value.rootfs_name!r}",
        f"OUTPUT = {'/out/' + output!r}",
        f"HOOKS = {value.hook_addresses!r}",
        f"STOPS = {value.stop_addresses!r}",
        f"MAX_INSTRUCTIONS = {value.max_instructions}",
        f"MAX_FIRMWARE_BYTES = {MAX_FIRMWARE_BYTES}",
        f"EXPECTED_ARCH_NAMES = {arch_tokens!r}",
        f"EXPECTED_BITS = {_ARCHES[value.architecture]}",
        f"EXPECTED_ENDIAN_TOKENS = {endian_tokens!r}",
        "firmware_size = Path(BINARY).stat().st_size",
        "if not 1 <= firmware_size <= MAX_FIRMWARE_BYTES:",
        "    raise ValueError('firmware image is empty or exceeds the 256 MiB plan cap')",
        "events = []",
        "count = 0",
        "ql = Qiling([BINARY], ROOTFS, verbose=QL_VERBOSE.OFF, multithread=False)",
        "detected_arch = ''.join(char for char in str(getattr(ql.arch.type, 'name', ql.arch.type)).lower() if char.isalnum())",
        "detected_bits = int(ql.arch.bits)",
        "detected_endian = str(getattr(ql.arch.endian, 'name', ql.arch.endian)).lower()",
        "detected_os = str(getattr(ql.os.type, 'name', ql.os.type)).lower()",
        "if detected_arch not in EXPECTED_ARCH_NAMES or detected_bits != EXPECTED_BITS:",
        "    raise ValueError('Qiling loader architecture/width disagrees with the reviewed manifest')",
        "if not any(token in detected_endian for token in EXPECTED_ENDIAN_TOKENS):",
        "    raise ValueError('Qiling loader endian disagrees with the reviewed manifest')",
        "if 'linux' not in detected_os:",
        "    raise ValueError('Qiling loader OS disagrees with the reviewed manifest')",
        "def code_hook(ql, address, size):",
        "    global count",
        "    count += 1",
        "    if address in HOOKS and len(events) < 256:",
        "        events.append({'address': address, 'size': size})",
        "    if address in STOPS or count >= MAX_INSTRUCTIONS:",
        "        ql.emu_stop()",
        "ql.hook_code(code_hook)",
        "ql.run()",
        "result = {'detected_arch': detected_arch, 'detected_bits': detected_bits, 'detected_endian': detected_endian, 'detected_os': detected_os, 'events': events, 'firmware_size': firmware_size, 'instructions': count, 'pc': int(ql.arch.regs.arch_pc)}",
        "with open(OUTPUT, 'w', encoding='utf-8') as handle:",
        "    json.dump(result, handle, sort_keys=True)",
    ]
    source = "\n".join(lines) + "\n"
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("generated Qiling source exceeds the cap")
    manifest = render_spec_manifest(value, "qiling")
    return EmulationPlan(
        engine="qiling",
        image="csctf-analysis:1",
        argv=("python3", "/plan/r5d_qiling_firmware.py"),
        generated_files=(("r5d_qiling_firmware.py", source), ("r5d_qiling_manifest.json", manifest)),
        expected_outputs=(output,),
        manifest=manifest,
        timeout_seconds=value.timeout_seconds,
        review_notes=_review_notes(value),
        runtime_requirements=("qiling",),
        image_build_required=True,
    )


_UNICORN = {
    ("x86", "little", "default"): ("UC_ARCH_X86", "UC_MODE_32", "UC_X86_REG_EIP", "unicorn.x86_const"),
    ("amd64", "little", "default"): ("UC_ARCH_X86", "UC_MODE_64", "UC_X86_REG_RIP", "unicorn.x86_const"),
    ("arm", "little", "arm"): ("UC_ARCH_ARM", "UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN", "UC_ARM_REG_PC", "unicorn.arm_const"),
    ("arm", "big", "arm"): ("UC_ARCH_ARM", "UC_MODE_ARM | UC_MODE_BIG_ENDIAN", "UC_ARM_REG_PC", "unicorn.arm_const"),
    ("arm", "little", "thumb"): ("UC_ARCH_ARM", "UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN", "UC_ARM_REG_PC", "unicorn.arm_const"),
    ("arm", "big", "thumb"): ("UC_ARCH_ARM", "UC_MODE_THUMB | UC_MODE_BIG_ENDIAN", "UC_ARM_REG_PC", "unicorn.arm_const"),
    ("arm", "little", "cortex-m"): ("UC_ARCH_ARM", "UC_MODE_THUMB | UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN", "UC_ARM_REG_PC", "unicorn.arm_const"),
    ("aarch64", "little", "default"): ("UC_ARCH_ARM64", "UC_MODE_LITTLE_ENDIAN", "UC_ARM64_REG_PC", "unicorn.arm64_const"),
    ("aarch64", "big", "default"): ("UC_ARCH_ARM64", "UC_MODE_BIG_ENDIAN", "UC_ARM64_REG_PC", "unicorn.arm64_const"),
    ("mips", "little", "default"): ("UC_ARCH_MIPS", "UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN", "UC_MIPS_REG_PC", "unicorn.mips_const"),
    ("mips", "big", "default"): ("UC_ARCH_MIPS", "UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN", "UC_MIPS_REG_PC", "unicorn.mips_const"),
    ("mips64", "little", "default"): ("UC_ARCH_MIPS", "UC_MODE_MIPS64 | UC_MODE_LITTLE_ENDIAN", "UC_MIPS_REG_PC", "unicorn.mips_const"),
    ("mips64", "big", "default"): ("UC_ARCH_MIPS", "UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN", "UC_MIPS_REG_PC", "unicorn.mips_const"),
    ("riscv32", "little", "default"): ("UC_ARCH_RISCV", "UC_MODE_RISCV32", "UC_RISCV_REG_PC", "unicorn.riscv_const"),
    ("riscv64", "little", "default"): ("UC_ARCH_RISCV", "UC_MODE_RISCV64", "UC_RISCV_REG_PC", "unicorn.riscv_const"),
}


def build_unicorn_plan(
    spec: FirmwareSpec | Mapping[str, object],
    *,
    output_name: str = "r5d_unicorn_trace.json",
) -> EmulationPlan:
    """Return a raw-firmware Unicorn plan; no emulator or artifact is loaded."""
    value = normalize_spec(spec)
    if value.format != "raw" or value.base_address is None or value.entrypoint is None:
        raise ValueError("Unicorn plans require raw firmware with explicit addresses")
    key = (value.architecture, value.endian, value.instruction_set)
    if key not in _UNICORN:
        raise ValueError("Unicorn plan does not support this architecture/endian pair")
    output = _name(output_name, "output")
    arch, mode, pc, register_module = _UNICORN[key]
    regions = tuple((region.address, region.size, region.permissions) for region in value.memory_regions)
    end = max(region.address + region.size for region in value.memory_regions)
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated plan: execute only in the networkless CSCTF Docker sandbox."""',
        "import json",
        "from unicorn import *",
        f"from {register_module} import {pc}",
        f"BINARY = {'/work/' + value.input_name!r}",
        f"OUTPUT = {'/out/' + output!r}",
        f"BASE = {value.base_address}",
        f"ENTRY = {value.entrypoint}",
        f"START = {value.entrypoint | 1 if value.instruction_set in {'thumb', 'cortex-m'} else value.entrypoint}",
        f"END = {end}",
        f"REGIONS = {regions!r}",
        f"HOOKS = {value.hook_addresses!r}",
        f"STOPS = {value.stop_addresses!r}",
        f"MAX_INSTRUCTIONS = {value.max_instructions}",
        f"TIMEOUT_US = {value.timeout_seconds * 1_000_000}",
        "with open(BINARY, 'rb') as handle:",
        f"    image = handle.read({MAX_FIRMWARE_BYTES + 1})",
        f"if not 1 <= len(image) <= {MAX_FIRMWARE_BYTES}:",
        "    raise ValueError('firmware image is empty or exceeds the 256 MiB plan cap')",
        f"uc = Uc({arch}, {mode})",
        "for address, size, permissions in REGIONS:",
        "    mask = (UC_PROT_READ if 'r' in permissions else 0) | (UC_PROT_WRITE if 'w' in permissions else 0) | (UC_PROT_EXEC if 'x' in permissions else 0)",
        "    uc.mem_map(address, size, mask)",
        "target = next((item for item in REGIONS if item[0] <= BASE < item[0] + item[1]), None)",
        "if target is None or BASE + len(image) > target[0] + target[1]:",
        "    raise ValueError('firmware image does not fit its mapped load region')",
        "if not BASE <= ENTRY < BASE + len(image):",
        "    raise ValueError('entrypoint is outside the loaded firmware bytes')",
        "uc.mem_write(BASE, image)",
        "events = []",
        "count = 0",
        "def code_hook(uc, address, size, _data):",
        "    global count",
        "    count += 1",
        "    if address in HOOKS and len(events) < 256:",
        "        events.append({'address': address, 'size': size})",
        "    if address in STOPS or count >= MAX_INSTRUCTIONS:",
        "        uc.emu_stop()",
        "uc.hook_add(UC_HOOK_CODE, code_hook)",
        "uc.emu_start(START, END, timeout=TIMEOUT_US, count=MAX_INSTRUCTIONS)",
        f"result = {{'events': events, 'instructions': count, 'pc': int(uc.reg_read({pc}))}}",
        "with open(OUTPUT, 'w', encoding='utf-8') as handle:",
        "    json.dump(result, handle, sort_keys=True)",
    ]
    source = "\n".join(lines) + "\n"
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("generated Unicorn source exceeds the cap")
    manifest = render_spec_manifest(value, "unicorn")
    return EmulationPlan(
        engine="unicorn",
        image="csctf-pwn:1",
        argv=("python3", "/plan/r5d_unicorn_firmware.py"),
        generated_files=(("r5d_unicorn_firmware.py", source), ("r5d_unicorn_manifest.json", manifest)),
        expected_outputs=(output,),
        manifest=manifest,
        timeout_seconds=value.timeout_seconds,
        review_notes=_review_notes(value),
        runtime_requirements=("unicorn",),
        image_build_required=False,
    )


def build_emulation_matrix(
    spec: FirmwareSpec | Mapping[str, object],
    *,
    engines: Sequence[str] | None = None,
) -> tuple[EmulationPlan, ...]:
    """Return the compatible canonical plans for a supplied metadata profile."""
    value = normalize_spec(spec)
    compatible = ("qiling",) if value.format == "elf" else ("unicorn",)
    requested = compatible if engines is None else tuple(engines)
    if not requested or len(requested) != len(set(requested)):
        raise ValueError("engines must be a non-empty sequence of distinct names")
    if any(engine not in compatible for engine in requested):
        raise ValueError(f"{value.format} firmware is compatible only with {compatible!r}")
    builders = {"qiling": lambda: build_qiling_plan(value), "unicorn": lambda: build_unicorn_plan(value)}
    return tuple(builders[engine]() for engine in compatible if engine in requested)


def render_plan_manifest(plans: Sequence[EmulationPlan]) -> str:
    try:
        plan_list = list(plans)
    except TypeError as exc:
        raise ValueError("plans must be a sequence of EmulationPlan values") from exc
    rows = []
    for plan in plan_list:
        if not isinstance(plan, EmulationPlan):
            raise ValueError("plans must contain EmulationPlan values")
        rows.append({
            "argv": list(plan.argv),
            "drop_capabilities": list(plan.drop_capabilities),
            "engine": plan.engine,
            "expected_outputs": list(plan.expected_outputs),
            "image": plan.image,
            "image_build_required": plan.image_build_required,
            "manifest": json.loads(plan.manifest),
            "network": plan.network,
            "read_only_root": plan.read_only_root,
            "review_notes": list(plan.review_notes),
            "runtime_requirements": list(plan.runtime_requirements),
            "timeout_seconds": plan.timeout_seconds,
        })
    return json.dumps(rows, sort_keys=True, separators=(",", ":"))


__all__ = [
    "EmulationPlan", "FirmwareSpec", "MemoryRegion", "build_emulation_matrix",
    "build_qiling_plan", "build_unicorn_plan", "normalize_spec",
    "render_plan_manifest", "render_spec_manifest",
]
