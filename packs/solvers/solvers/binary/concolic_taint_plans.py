"""Build bounded, reviewable concolic and taint-analysis plans.

This module only validates metadata and returns source/argv/manifest strings.
It never imports angr or Triton, opens an artifact, launches a process, or
executes generated source. Generated files are intended for the repository's
networkless Docker sandbox after review.

Unlike :mod:`symbolic_harness`, these plans start from a concrete seed and
symbolize selected offsets. The Triton plan consumes a separately supplied,
bounded instruction trace so artifact decoding and execution stay in Docker.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Mapping, Sequence


MAX_SEED_BYTES = 4096
MAX_SYMBOLIC_OFFSETS = 256
MAX_GOALS = 256
MAX_TRACE_ADDRESSES = 8192
MAX_TRACE_BYTES = 8 << 20
MAX_STEPS = 1_000_000
MAX_ACTIVE = 4096
MAX_TIMEOUT = 1800
MAX_SOURCE_CHARS = 2 << 20

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LITERAL_ADDRESS = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)\Z")
_ARCHES = {
    "x86": ("X86", "ARCH.X86"),
    "amd64": ("AMD64", "ARCH.X86_64"),
    "arm": ("ARMEL", "ARCH.ARM32"),
    "aarch64": ("AARCH64", "ARCH.AARCH64"),
    "mips": ("MIPS32", "ARCH.MIPS32"),
    "riscv64": ("RISCV64", "ARCH.RV64"),
}
_SPEC_KEYS = {
    "input_name", "architecture", "mode", "seed", "seed_hex",
    "symbolic_offsets", "find", "avoid", "taint_sinks", "trace",
    "input_address", "base_address", "entrypoint", "max_steps", "max_active",
    "solution_limit", "timeout_seconds",
}


@dataclass(frozen=True)
class ConcolicSpec:
    """Normalized concrete-seed analysis request."""

    input_name: str
    architecture: str
    mode: str
    seed: bytes
    symbolic_offsets: tuple[int, ...]
    find: tuple[int, ...] = ()
    avoid: tuple[int, ...] = ()
    taint_sinks: tuple[int, ...] = ()
    trace: tuple[int, ...] = ()
    input_address: int | None = None
    base_address: int | None = None
    entrypoint: int | None = None
    max_steps: int = 50_000
    max_active: int = 256
    solution_limit: int = 4
    timeout_seconds: int = 600

    @classmethod
    def from_mapping(cls, raw: "ConcolicSpec | Mapping[str, object]") -> "ConcolicSpec":
        if isinstance(raw, cls):
            raw = asdict(raw)
        if not isinstance(raw, Mapping):
            raise ValueError("concolic specification must be a mapping")
        unknown = sorted(str(key) for key in raw if key not in _SPEC_KEYS)
        if unknown:
            raise ValueError(f"unknown concolic specification key(s): {unknown!r}")

        input_name = _name(raw.get("input_name", "challenge.bin"), "input")
        architecture = raw.get("architecture", "amd64")
        if not isinstance(architecture, str) or architecture not in _ARCHES:
            raise ValueError("unsupported concolic architecture")
        mode = raw.get("mode", "stdin")
        if not isinstance(mode, str) or mode not in {"stdin", "argv", "file"}:
            raise ValueError("mode must be stdin, argv, or file")
        seed = _seed(raw)
        offsets = _offsets(raw.get("symbolic_offsets"), len(seed))
        find = _addresses(raw.get("find", ()), "find", MAX_GOALS)
        avoid = _addresses(raw.get("avoid", ()), "avoid", MAX_GOALS)
        sinks = _addresses(raw.get("taint_sinks", ()), "taint_sinks", MAX_GOALS)
        trace = _trace_addresses(raw.get("trace", ()))
        if not find and not sinks:
            raise ValueError("at least one find address or taint sink is required")
        if set(find) & set(avoid):
            raise ValueError("find and avoid addresses must not overlap")
        base = _optional_address(raw.get("base_address"), "base_address")
        entry = _optional_address(raw.get("entrypoint"), "entrypoint")
        input_address = _optional_address(raw.get("input_address"), "input_address")
        if input_address is not None and input_address + len(seed) > 1 << 64:
            raise ValueError("input_address plus seed length exceeds the address space")
        if (base is None) != (entry is None):
            raise ValueError("base_address and entrypoint must be supplied together")
        if base is not None and entry is not None and entry < base:
            raise ValueError("entrypoint must not precede base_address")

        return cls(
            input_name=input_name,
            architecture=str(architecture),
            mode=str(mode),
            seed=seed,
            symbolic_offsets=offsets,
            find=find,
            avoid=avoid,
            taint_sinks=sinks,
            trace=trace,
            input_address=input_address,
            base_address=base,
            entrypoint=entry,
            max_steps=_bounded_int(raw.get("max_steps", 50_000), "max_steps", 1, MAX_STEPS),
            max_active=_bounded_int(raw.get("max_active", 256), "max_active", 1, MAX_ACTIVE),
            solution_limit=_bounded_int(raw.get("solution_limit", 4), "solution_limit", 1, 64),
            timeout_seconds=_bounded_int(
                raw.get("timeout_seconds", 600), "timeout_seconds", 1, MAX_TIMEOUT
            ),
        )


@dataclass(frozen=True)
class AnalysisPlan:
    engine: str
    image: str
    argv: tuple[str, ...]
    generated_files: tuple[tuple[str, str], ...]
    expected_outputs: tuple[str, ...]
    manifest: str
    timeout_seconds: int
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
            raise ValueError(f"{field} must contain only literal addresses")
        value = int(value, 16 if value.lower().startswith("0x") else 10)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError(f"{field} address is outside the unsigned 64-bit range")
    return value


def _optional_address(value: object, field: str) -> int | None:
    return None if value is None else _address(value, field)


def _addresses(value: object, field: str, cap: int) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list)) or len(value) > cap:
        raise ValueError(f"{field} must contain at most {cap} addresses")
    return tuple(sorted({_address(item, field) for item in value}))


def _trace_addresses(value: object) -> tuple[int, ...]:
    """Preserve replay order and repeated loop addresses."""
    if not isinstance(value, (tuple, list)) or len(value) > MAX_TRACE_ADDRESSES:
        raise ValueError(f"trace must contain at most {MAX_TRACE_ADDRESSES} addresses")
    return tuple(_address(item, "trace") for item in value)


def _seed(raw: Mapping[str, object]) -> bytes:
    plain = raw.get("seed")
    hexa = raw.get("seed_hex")
    if plain is not None and hexa is not None:
        raise ValueError("choose either seed or seed_hex")
    if hexa is not None:
        if (not isinstance(hexa, str) or len(hexa) % 2
                or not 2 <= len(hexa) <= MAX_SEED_BYTES * 2):
            raise ValueError("seed_hex must be bounded, non-empty, even-length hexadecimal")
        try:
            value = bytes.fromhex(hexa)
        except ValueError as exc:
            raise ValueError("seed_hex is not hexadecimal") from exc
    elif isinstance(plain, str):
        try:
            value = plain.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("seed text is not encodable as UTF-8") from exc
    elif isinstance(plain, bytes):
        value = plain
    else:
        raise ValueError("seed or seed_hex is required")
    if not 1 <= len(value) <= MAX_SEED_BYTES:
        raise ValueError(f"seed must contain 1..{MAX_SEED_BYTES} bytes")
    return value


def _offsets(value: object, seed_length: int) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= MAX_SYMBOLIC_OFFSETS:
        raise ValueError(f"symbolic_offsets must contain 1..{MAX_SYMBOLIC_OFFSETS} offsets")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
        raise ValueError("symbolic_offsets must be integers")
    result = tuple(sorted(set(value)))
    if len(result) != len(value):
        raise ValueError("symbolic_offsets must be distinct")
    if result[0] < 0 or result[-1] >= seed_length:
        raise ValueError("symbolic offset lies outside the concrete seed")
    return result


def normalize_spec(spec: ConcolicSpec | Mapping[str, object]) -> ConcolicSpec:
    return ConcolicSpec.from_mapping(spec)


def _manifest_dict(value: ConcolicSpec, engine: str) -> dict[str, object]:
    return {
        "architecture": value.architecture,
        "avoid": list(value.avoid),
        "base_address": value.base_address,
        "engine": engine,
        "entrypoint": value.entrypoint,
        "find": list(value.find),
        "input_address": value.input_address,
        "input_name": value.input_name,
        "limits": {
            "active_states": value.max_active,
            "solutions": value.solution_limit,
            "steps_or_instructions": value.max_steps,
            "timeout_seconds": value.timeout_seconds,
        },
        "mode": value.mode,
        "network": "none",
        "sandbox_required": True,
        "seed_hex": value.seed.hex(),
        "symbolic_offsets": list(value.symbolic_offsets),
        "taint_sinks": list(value.taint_sinks),
        "trace": list(value.trace),
    }


def render_spec_manifest(
    spec: ConcolicSpec | Mapping[str, object],
    engine: str,
    *,
    trace_name: str | None = None,
) -> str:
    value = normalize_spec(spec)
    if not isinstance(engine, str) or engine not in {"angr", "triton"}:
        raise ValueError("engine must be angr or triton")
    row = _manifest_dict(value, engine)
    if engine == "triton":
        row["trace_name"] = _name(
            "r5d_instruction_trace.json" if trace_name is None else trace_name,
            "trace",
        )
        row["trace_contract"] = 1
        row["trace_reconciliation"] = "pre-instruction"
    elif trace_name is not None:
        raise ValueError("trace_name is accepted only for Triton manifests")
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _angr_state_lines(value: ConcolicSpec) -> list[str]:
    if value.mode == "stdin":
        return [
            "stream = angr.SimFileStream(name='stdin', content=mixed, has_end=True)",
            "state = project.factory.full_init_state(stdin=stream)",
        ]
    if value.mode == "argv":
        return ["state = project.factory.full_init_state(args=[BINARY, mixed])"]
    return [
        "state = project.factory.full_init_state(args=[BINARY, INPUT_FILE])",
        "state.fs.insert(INPUT_FILE, angr.SimFile(INPUT_FILE, content=mixed, size=len(SEED)))",
    ]


def build_angr_concolic_plan(
    spec: ConcolicSpec | Mapping[str, object],
    *,
    output_name: str = "r5d_angr_concolic.json",
) -> AnalysisPlan:
    """Return an angr concrete-seed plan without importing or running angr."""
    value = normalize_spec(spec)
    output = _name(output_name, "output")
    main_options: dict[str, object] = {}
    if value.base_address is not None:
        main_options = {
            "backend": "blob",
            "arch": _ARCHES[value.architecture][0],
            "base_addr": value.base_address,
            "entry_point": value.entrypoint,
        }
    kwargs: dict[str, object] = {"auto_load_libs": False}
    if main_options:
        kwargs["main_opts"] = main_options
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated plan: execute only in the networkless CSCTF Docker sandbox."""',
        "import json",
        "import angr",
        "import claripy",
        f"BINARY = {'/work/' + value.input_name!r}",
        "INPUT_FILE = '/tmp/r5d_concolic_seed'",
        f"SEED = bytes.fromhex({value.seed.hex()!r})",
        f"SYMBOLIC_OFFSETS = {value.symbolic_offsets!r}",
        f"FIND = {value.find!r}",
        f"AVOID = {value.avoid!r}",
        f"TAINT_SINKS = {value.taint_sinks!r}",
        f"TRACE = {value.trace!r}",
        f"MAX_STEPS = {value.max_steps}",
        f"MAX_ACTIVE = {value.max_active}",
        f"SOLUTION_LIMIT = {value.solution_limit}",
        f"project = angr.Project(BINARY, **{kwargs!r})",
        "symbolic = {index: claripy.BVS(f'r5d_seed_{index}', 8) for index in SYMBOLIC_OFFSETS}",
        "parts = [symbolic.get(index, claripy.BVV(byte, 8)) for index, byte in enumerate(SEED)]",
        "mixed = claripy.Concat(*parts)",
    ]
    lines.extend(_angr_state_lines(value))
    lines.extend([
        "state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)",
        "state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)",
        "manager = project.factory.simgr(state)",
        "if TRACE:",
        "    manager.use_technique(angr.exploration_techniques.Tracer(trace=list(TRACE), copy_states=True))",
        "goals = tuple(sorted(set(FIND) | set(TAINT_SINKS)))",
        "manager.use_technique(angr.exploration_techniques.Explorer(",
        "    find=lambda candidate: candidate.addr in goals,",
        "    avoid=lambda candidate: candidate.addr in AVOID,",
        "    num_find=1,",
        "))",
        "steps = 0",
        "while manager.active and not manager.found and steps < MAX_STEPS:",
        "    manager.step()",
        "    steps += 1",
        "    if len(manager.active) > MAX_ACTIVE:",
        "        manager.stashes.setdefault('r5d_deferred', []).extend(manager.active[MAX_ACTIVE:])",
        "        manager.stashes['active'] = manager.active[:MAX_ACTIVE]",
        "models = []",
        "ambiguous = False",
        "symbolic_names = {str(item.args[0]) for item in symbolic.values()}",
        "path_dependencies = []",
        "for found in manager.found[:1]:",
        "    raw_models = found.solver.eval_upto(mixed, SOLUTION_LIMIT + 1, cast_to=bytes)",
        "    ambiguous = len(raw_models) > SOLUTION_LIMIT",
        "    for model in raw_models[:SOLUTION_LIMIT]:",
        "        if model not in models:",
        "            models.append(model)",
        "    if found.addr in TAINT_SINKS:",
        "        constraints = ' '.join(map(str, found.solver.constraints))",
        "        path_dependencies = sorted(name for name in symbolic_names if name in constraints)",
        "result = {",
        "    'ambiguous': ambiguous,",
        "    'candidates_hex': [item.hex() for item in models],",
        "    'deferred_states': len(manager.stashes.get('r5d_deferred', [])),",
        "    'found_addresses': sorted({found.addr for found in manager.found}),",
        "    'path_constraint_symbol_dependencies': path_dependencies,",
        "    'sink_data_taint_analyzed': False,",
        "    'steps': steps,",
        "}",
        f"with open({'/out/' + output!r}, 'w', encoding='utf-8') as handle:",
        "    json.dump(result, handle, sort_keys=True)",
    ])
    source = "\n".join(lines) + "\n"
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("generated angr concolic source exceeds the cap")
    manifest = render_spec_manifest(value, "angr")
    return AnalysisPlan(
        engine="angr-concolic",
        image="csctf-analysis:1",
        argv=("python3", "/plan/r5d_angr_concolic.py"),
        generated_files=(
            ("r5d_angr_concolic.py", source),
            ("r5d_angr_concolic_manifest.json", manifest),
        ),
        expected_outputs=(output,),
        manifest=manifest,
        timeout_seconds=value.timeout_seconds,
        runtime_requirements=("angr", "claripy"),
        image_build_required=True,
    )


def build_triton_taint_plan(
    spec: ConcolicSpec | Mapping[str, object],
    *,
    trace_name: str = "r5d_instruction_trace.json",
    output_name: str = "r5d_triton_taint.json",
) -> AnalysisPlan:
    """Return a Triton plan over a supplied stateful instruction trace.

    The Docker-side trace contract contains architecture/input bindings,
    initial register/memory state, and ordered instruction records. Records
    may carry concrete register/memory reconciliation snapshots. This avoids
    claiming meaningful taint from address/opcode pairs alone.
    """
    value = normalize_spec(spec)
    if not value.taint_sinks:
        raise ValueError("Triton taint plans require at least one taint sink")
    if value.input_address is None:
        raise ValueError("Triton taint plans require an explicit input_address")
    trace_file = _name(trace_name, "trace")
    output = _name(output_name, "output")
    triton_arch = _ARCHES[value.architecture][1]
    # Triton's published architecture_e lists ARM32/AARCH64/RV32/RV64/X86/X86_64 only;
    # there is no ARCH.MIPS* enum, so decline a MIPS taint plan rather than emit an invalid one.
    if triton_arch not in {"ARCH.X86", "ARCH.X86_64", "ARCH.ARM32", "ARCH.AARCH64",
                           "ARCH.RV32", "ARCH.RV64"}:
        raise ValueError(f"Triton does not support architecture {value.architecture!r}")
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated plan: execute only in the networkless CSCTF Docker sandbox."""',
        "import json",
        "from triton import ARCH, Instruction, MemoryAccess, TritonContext",
        f"TRACE_PATH = {'/work/' + trace_file!r}",
        f"OUTPUT_PATH = {'/out/' + output!r}",
        f"SEED = bytes.fromhex({value.seed.hex()!r})",
        f"SYMBOLIC_OFFSETS = {value.symbolic_offsets!r}",
        f"TAINT_SINKS = {value.taint_sinks!r}",
        f"MAX_INSTRUCTIONS = {value.max_steps}",
        f"MAX_TRACE_BYTES = {MAX_TRACE_BYTES}",
        f"TRACE_ARCHITECTURE = {value.architecture!r}",
        f"INPUT_BASE = {value.input_address}",
        "ctx = TritonContext()",
        f"ctx.setArchitecture({triton_arch})",
        "def checked_int(value, label):",
        "    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):",
        "        raise ValueError(f'invalid {label}')",
        "    return value",
        "def apply_registers(values, label):",
        "    if not isinstance(values, dict) or len(values) > 128:",
        "        raise ValueError(f'{label} must be a bounded register mapping')",
        "    for name, raw_value in values.items():",
        "        if not isinstance(name, str) or not 1 <= len(name) <= 32 or not name.replace('_', '').isalnum():",
        "            raise ValueError(f'invalid register name in {label}')",
        "        value = checked_int(raw_value, f'{label} register value')",
        "        register = ctx.getRegister(name)",
        "        if register is None:",
        "            raise ValueError(f'unknown register in {label}: {name}')",
        "        ctx.setConcreteRegisterValue(register, value)",
        "def decode_memory(values, label, row_cap, byte_cap):",
        "    if not isinstance(values, list) or len(values) > row_cap:",
        "        raise ValueError(f'{label} must be a bounded memory list')",
        "    rows = []",
        "    total = 0",
        "    for row in values:",
        "        if not isinstance(row, dict) or set(row) != {'address', 'bytes_hex'}:",
        "            raise ValueError(f'malformed {label} row')",
        "        address = checked_int(row.get('address'), f'{label} address')",
        "        hexa = row.get('bytes_hex')",
        "        if not isinstance(hexa, str) or not hexa or len(hexa) % 2 or len(hexa) > byte_cap * 2:",
        "            raise ValueError(f'invalid {label} bytes_hex')",
        "        try:",
        "            blob = bytes.fromhex(hexa)",
        "        except ValueError as exc:",
        "            raise ValueError(f'non-hexadecimal {label} bytes') from exc",
        "        total += len(blob)",
        "        if address + len(blob) > (1 << 64):",
        "            raise ValueError(f'{label} row exceeds the address space')",
        "        if total > byte_cap:",
        "            raise ValueError(f'{label} exceeds its byte cap')",
        "        rows.append((address, blob))",
        "    return rows",
        "def apply_memory(rows):",
        "    for address, blob in rows:",
        "        for offset, byte in enumerate(blob):",
        "            ctx.setConcreteMemoryValue(MemoryAccess(address + offset, 1), byte)",
        "with open(TRACE_PATH, 'rb') as handle:",
        "    trace_bytes = handle.read(MAX_TRACE_BYTES + 1)",
        "if len(trace_bytes) > MAX_TRACE_BYTES:",
        "    raise ValueError('instruction trace exceeds the byte cap')",
        "try:",
        "    trace = json.loads(trace_bytes)",
        "except (UnicodeDecodeError, json.JSONDecodeError) as exc:",
        "    raise ValueError('instruction trace is not bounded UTF-8 JSON') from exc",
        "required = {'contract_version', 'reconciliation', 'architecture', 'input_address', 'initial_registers', 'initial_memory', 'instructions'}",
        "if not isinstance(trace, dict) or set(trace) != required:",
        "    raise ValueError('instruction trace has the wrong top-level contract')",
        "if trace['contract_version'] != 1 or trace['reconciliation'] != 'pre-instruction':",
        "    raise ValueError('unsupported instruction-trace contract or reconciliation phase')",
        "if trace['architecture'] != TRACE_ARCHITECTURE:",
        "    raise ValueError('instruction trace architecture mismatch')",
        "if checked_int(trace['input_address'], 'trace input_address') != INPUT_BASE:",
        "    raise ValueError('instruction trace input_address mismatch')",
        "apply_registers(trace['initial_registers'], 'initial_registers')",
        "apply_memory(decode_memory(trace['initial_memory'], 'initial_memory', 256, 1048576))",
        "for index, byte in enumerate(SEED):",
        "    memory = MemoryAccess(INPUT_BASE + index, 1)",
        "    ctx.setConcreteMemoryValue(memory, byte)",
        "    if index in SYMBOLIC_OFFSETS:",
        "        ctx.symbolizeMemory(memory, f'r5d_seed_{index}')",
        "        ctx.taintMemory(memory)",
        "instructions = trace['instructions']",
        "if not isinstance(instructions, list) or not 1 <= len(instructions) <= MAX_INSTRUCTIONS:",
        "    raise ValueError('instructions must be a non-empty bounded list')",
        "hits = []",
        "hits_truncated = False",
        "processed = 0",
        "for record in instructions:",
        "    allowed = {'address', 'opcode_hex', 'registers', 'memory_writes'}",
        "    if not isinstance(record, dict) or set(record) - allowed or not {'address', 'opcode_hex'} <= set(record):",
        "        raise ValueError('malformed instruction trace record')",
        "    address = checked_int(record.get('address'), 'instruction address')",
        "    opcode_hex = record.get('opcode_hex')",
        "    if not isinstance(opcode_hex, str) or not 2 <= len(opcode_hex) <= 64 or len(opcode_hex) % 2:",
        "        raise ValueError('invalid bounded opcode_hex')",
        "    try:",
        "        opcode = bytes.fromhex(opcode_hex)",
        "    except ValueError as exc:",
        "        raise ValueError('opcode_hex is not hexadecimal') from exc",
        "    apply_registers(record.get('registers', {}), 'instruction registers')",
        "    apply_memory(decode_memory(record.get('memory_writes', []), 'memory_writes', 32, 65536))",
        "    instruction = Instruction(address, opcode)",
        "    ctx.processing(instruction)",
        "    processed += 1",
        "    if address in TAINT_SINKS:",
        "        aliases = []",
        "        for expression in instruction.getSymbolicExpressions():",
        "            for variable in expression.getAst().getSymbolicVariables().values():",
        "                alias = str(variable.getAlias() or variable.getName())[:128]",
        "                if alias not in aliases and len(aliases) < 256:",
        "                    aliases.append(alias)",
        "        tainted_registers = []",
        "        for register, _node in instruction.getReadRegisters():",
        "            if ctx.isRegisterTainted(register) and len(tainted_registers) < 128:",
        "                tainted_registers.append(str(register)[:64])",
        "        tainted_loads = []",
        "        for memory, _node in instruction.getLoadAccess():",
        "            if ctx.isMemoryTainted(memory) and len(tainted_loads) < 128:",
        "                tainted_loads.append({'address': memory.getAddress(), 'size': memory.getSize()})",
        "        row = {'address': address, 'symbolic_input_aliases': sorted(aliases), 'tainted_loads': tainted_loads, 'tainted_registers': sorted(set(tainted_registers))}",
        "        if len(hits) < 256:",
        "            hits.append(row)",
        "        else:",
        "            hits_truncated = True",
        "result = {'processed': processed, 'sink_hits': hits, 'sink_hits_truncated': hits_truncated, 'trace_contract': 1}",
        "with open(OUTPUT_PATH, 'w', encoding='utf-8') as handle:",
        "    json.dump(result, handle, sort_keys=True)",
    ]
    source = "\n".join(lines) + "\n"
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("generated Triton source exceeds the cap")
    manifest = render_spec_manifest(value, "triton", trace_name=trace_file)
    return AnalysisPlan(
        engine="triton-taint",
        image="csctf-analysis:1",
        argv=("python3", "/plan/r5d_triton_taint.py"),
        generated_files=(
            ("r5d_triton_taint.py", source),
            ("r5d_triton_taint_manifest.json", manifest),
        ),
        expected_outputs=(output,),
        manifest=manifest,
        timeout_seconds=value.timeout_seconds,
        runtime_requirements=("triton-library",),
        image_build_required=True,
    )


def build_analysis_matrix(
    spec: ConcolicSpec | Mapping[str, object],
    *,
    engines: Sequence[str] | None = None,
) -> tuple[AnalysisPlan, ...]:
    """Build a canonical plan tuple; no plan is executed."""
    value = normalize_spec(spec)
    default_engines = (
        ("angr", "triton")
        if value.taint_sinks and value.input_address is not None
        else ("angr",)
    )
    if engines is None:
        requested = default_engines
    else:
        try:
            requested = tuple(engines)
        except TypeError as exc:
            raise ValueError("engines must be a sequence of engine names") from exc
    if any(not isinstance(name, str) for name in requested):
        raise ValueError("engines must be a sequence of engine names")
    if not requested or len(requested) != len(set(requested)):
        raise ValueError("engines must be a non-empty sequence of distinct names")
    if any(engine not in {"angr", "triton"} for engine in requested):
        raise ValueError("unsupported concolic/taint engine")
    builders = {
        "angr": lambda: build_angr_concolic_plan(value),
        "triton": lambda: build_triton_taint_plan(value),
    }
    return tuple(builders[name]() for name in ("angr", "triton") if name in requested)


def render_plan_manifest(plans: Sequence[AnalysisPlan]) -> str:
    """Return canonical JSON for review without embedding generated source."""
    try:
        plan_list = list(plans)
    except TypeError as exc:
        raise ValueError("plans must be a sequence of AnalysisPlan values") from exc
    rows = []
    for plan in plan_list:
        if not isinstance(plan, AnalysisPlan):
            raise ValueError("plans must contain AnalysisPlan values")
        try:
            parsed_manifest = json.loads(plan.manifest)
        except json.JSONDecodeError as exc:
            raise ValueError("plan manifest is not valid JSON") from exc
        rows.append({
            "argv": list(plan.argv),
            "drop_capabilities": list(plan.drop_capabilities),
            "engine": plan.engine,
            "expected_outputs": list(plan.expected_outputs),
            "image": plan.image,
            "image_build_required": plan.image_build_required,
            "manifest": parsed_manifest,
            "network": plan.network,
            "read_only_root": plan.read_only_root,
            "runtime_requirements": list(plan.runtime_requirements),
            "timeout_seconds": plan.timeout_seconds,
        })
    return json.dumps(rows, sort_keys=True, separators=(",", ":"))


__all__ = [
    "AnalysisPlan", "ConcolicSpec", "build_analysis_matrix",
    "build_angr_concolic_plan", "build_triton_taint_plan", "normalize_spec",
    "render_plan_manifest", "render_spec_manifest",
]
