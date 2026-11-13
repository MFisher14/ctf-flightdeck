"""Generate reviewable, bounded symbolic-execution harness source.

This module is a *source generator*.  Importing it never imports angr, opens a
challenge binary, launches a process, or executes artifact-derived code.  The
returned script is intended for deliberate execution inside the repository's
networkless Docker sandbox after a human reviews the normalized manifest.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Mapping, Sequence


MAX_SYMBOLIC_BYTES = 4096
MAX_FIND = 64
MAX_AVOID = 256
MAX_STEPS = 1_000_000
MAX_ACTIVE = 4096
MAX_SOURCE_CHARS = 2 << 20

_ARCH_HINTS = {"x86", "amd64", "arm", "aarch64", "mips", "ppc", "ppc64", "riscv"}
_BLOB_ARCHES = {
    "x86": "X86", "amd64": "AMD64", "arm": "ARMEL", "aarch64": "AARCH64",
    "mips": "MIPS32", "ppc": "PPC32", "ppc64": "PPC64", "riscv": "RISCV64",
}
_ADDRESS = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)\Z")
_SPEC_KEYS = {
    "binary", "mode", "length", "find", "avoid", "prefix", "prefix_hex",
    "suffix", "suffix_hex", "alphabet", "file_path", "state_factory",
    "architecture_hint", "blob_arch", "base_addr", "entry_addr", "max_steps",
    "max_active", "solution_limit", "zero_fill",
}


@dataclass(frozen=True)
class SymbolicSpec:
    binary: str
    mode: str
    length: int
    find: tuple[int, ...]
    avoid: tuple[int, ...] = ()
    prefix: bytes = b""
    suffix: bytes = b""
    alphabet: tuple[int, ...] = tuple(range(0x20, 0x7F))
    file_path: str = "/tmp/r5d_symbolic_input"
    state_factory: str = "full_init"
    architecture_hint: str | None = None
    blob_arch: str | None = None
    base_addr: int | None = None
    entry_addr: int | None = None
    max_steps: int = 50_000
    max_active: int = 256
    solution_limit: int = 4
    zero_fill: bool = True

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "SymbolicSpec":
        """Validate and normalize the declarative, expression-free input."""
        if not isinstance(raw, Mapping):
            raise TypeError("symbolic specification must be a mapping")
        unknown = [key for key in raw if key not in _SPEC_KEYS]
        if unknown:
            raise ValueError(f"unknown symbolic specification key(s): {sorted(map(repr, unknown))}")
        binary = _safe_path(raw.get("binary", "/chal/challenge"), "binary")
        mode = raw.get("mode", "stdin")
        if mode not in {"stdin", "argv", "file"}:
            raise ValueError("mode must be stdin, argv, or file")
        length = _bounded_int(raw.get("length"), "length", 1, MAX_SYMBOLIC_BYTES)
        find = _address_list(raw.get("find"), "find", 1, MAX_FIND)
        avoid = _address_list(raw.get("avoid", ()), "avoid", 0, MAX_AVOID)
        if set(find) & set(avoid):
            raise ValueError("find and avoid addresses must not overlap")
        prefix = _byte_value(raw, "prefix")
        suffix = _byte_value(raw, "suffix")
        if len(prefix) + len(suffix) > length:
            raise ValueError("prefix and suffix exceed symbolic input length")
        alphabet = _alphabet(raw.get("alphabet", "printable"))
        file_path = _safe_path(raw.get("file_path", "/tmp/r5d_symbolic_input"), "file_path")
        state_factory = raw.get("state_factory", "full_init")
        if state_factory not in {"full_init", "entry"}:
            raise ValueError("state_factory must be full_init or entry")
        architecture_hint = raw.get("architecture_hint")
        if architecture_hint is not None:
            if not isinstance(architecture_hint, str) or architecture_hint not in _ARCH_HINTS:
                raise ValueError("unsupported architecture_hint")
        blob_arch = raw.get("blob_arch")
        if blob_arch is not None:
            if not isinstance(blob_arch, str) or blob_arch not in _BLOB_ARCHES:
                raise ValueError("unsupported blob_arch")
        base_addr = _optional_address(raw.get("base_addr"), "base_addr")
        entry_addr = _optional_address(raw.get("entry_addr"), "entry_addr")
        if blob_arch is not None and (base_addr is None or entry_addr is None):
            raise ValueError("blob_arch requires base_addr and entry_addr")
        if blob_arch is not None and entry_addr is not None and base_addr is not None and entry_addr < base_addr:
            raise ValueError("raw-blob entry_addr must not precede base_addr")
        if blob_arch is None and entry_addr is not None:
            raise ValueError("entry_addr is accepted only for a raw blob")
        max_steps = _bounded_int(raw.get("max_steps", 50_000), "max_steps", 1, MAX_STEPS)
        max_active = _bounded_int(raw.get("max_active", 256), "max_active", 1, MAX_ACTIVE)
        solution_limit = _bounded_int(raw.get("solution_limit", 4), "solution_limit", 1, 64)
        zero_fill = raw.get("zero_fill", True)
        if not isinstance(zero_fill, bool):
            raise ValueError("zero_fill must be boolean")
        return cls(
            binary=binary,
            mode=str(mode),
            length=length,
            find=find,
            avoid=avoid,
            prefix=prefix,
            suffix=suffix,
            alphabet=alphabet,
            file_path=file_path,
            state_factory=str(state_factory),
            architecture_hint=architecture_hint,
            blob_arch=blob_arch,
            base_addr=base_addr,
            entry_addr=entry_addr,
            max_steps=max_steps,
            max_active=max_active,
            solution_limit=solution_limit,
            zero_fill=zero_fill,
        )


def _bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _safe_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError(f"{name} path is invalid")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ValueError(f"{name} path contains a control character")
    return value


def _address_value(value: object, name: str) -> int:
    if isinstance(value, str):
        if not _ADDRESS.fullmatch(value):
            raise ValueError(f"{name} contains a non-literal address")
        value = int(value, 16 if value.lower().startswith("0x") else 10)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError(f"{name} is outside the unsigned 64-bit range")
    return value


def _optional_address(value: object, name: str) -> int | None:
    return None if value is None else _address_value(value, name)


def _address_list(value: object, name: str, minimum: int, maximum: int) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{name} must contain {minimum}..{maximum} addresses")
    normalized = tuple(sorted({_address_value(item, name) for item in value}))
    if len(normalized) < minimum:
        raise ValueError(f"{name} does not contain enough distinct addresses")
    return normalized


def _byte_value(raw: Mapping[str, object], name: str) -> bytes:
    plain = raw.get(name)
    hexa = raw.get(name + "_hex")
    if plain is not None and hexa is not None:
        raise ValueError(f"choose either {name} or {name}_hex")
    if hexa is not None:
        if not isinstance(hexa, str) or len(hexa) % 2 or len(hexa) > MAX_SYMBOLIC_BYTES * 2:
            raise ValueError(f"{name}_hex must be bounded even-length hexadecimal")
        try:
            return bytes.fromhex(hexa)
        except ValueError as exc:
            raise ValueError(f"{name}_hex is not hexadecimal") from exc
    if plain is None:
        return b""
    if isinstance(plain, str):
        value = plain.encode("utf-8")
    elif isinstance(plain, bytes):
        value = plain
    else:
        raise ValueError(f"{name} must be text or bytes")
    if len(value) > MAX_SYMBOLIC_BYTES:
        raise ValueError(f"{name} exceeds the byte cap")
    return value


def _alphabet(value: object) -> tuple[int, ...]:
    if value == "printable":
        return tuple(range(0x20, 0x7F))
    if value == "alnum":
        return tuple(sorted(set(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")))
    if value == "bytes":
        return tuple(range(256))
    if isinstance(value, bytes):
        values: Sequence[object] = tuple(value)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        raise ValueError("alphabet must be printable, alnum, bytes, or a byte sequence")
    if not 1 <= len(values) <= 256:
        raise ValueError("alphabet must contain 1..256 bytes")
    if any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in values):
        raise ValueError("alphabet contains a non-byte value")
    return tuple(sorted(set(int(item) for item in values)))


def normalize_spec(spec: SymbolicSpec | Mapping[str, object]) -> SymbolicSpec:
    if isinstance(spec, SymbolicSpec):
        # Round-trip dataclass instances through the validator as well; callers
        # cannot bypass bounds by constructing a dataclass directly.
        raw = asdict(spec)
        raw["prefix"] = spec.prefix
        raw["suffix"] = spec.suffix
        raw["alphabet"] = spec.alphabet
        return SymbolicSpec.from_mapping(raw)
    return SymbolicSpec.from_mapping(spec)


def render_manifest(spec: SymbolicSpec | Mapping[str, object]) -> str:
    """Return canonical JSON suitable for review beside the generated source."""
    value = normalize_spec(spec)
    manifest = {
        "architecture_hint": value.architecture_hint,
        "alphabet_hex": bytes(value.alphabet).hex(),
        "avoid": list(value.avoid),
        "base_addr": value.base_addr,
        "binary": value.binary,
        "blob_arch": value.blob_arch,
        "entry_addr": value.entry_addr,
        "file_path": value.file_path if value.mode == "file" else None,
        "find": list(value.find),
        "length": value.length,
        "limits": {
            "active_states": value.max_active,
            "solutions_per_state": value.solution_limit,
            "steps": value.max_steps,
        },
        "mode": value.mode,
        "prefix_hex": value.prefix.hex(),
        "sandbox_required": True,
        "state_factory": value.state_factory,
        "suffix_hex": value.suffix.hex(),
        "zero_fill": value.zero_fill,
    }
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"))


def _state_lines(value: SymbolicSpec) -> list[str]:
    factory = "full_init_state" if value.state_factory == "full_init" else "entry_state"
    if value.mode == "stdin":
        return [
            "stream = angr.SimFileStream(name='stdin', content=symbolic, has_end=True)",
            f"state = project.factory.{factory}(stdin=stream)",
        ]
    if value.mode == "argv":
        return [f"state = project.factory.{factory}(args=[BINARY, symbolic])"]
    return [
        f"state = project.factory.{factory}(args=[BINARY, FILE_PATH])",
        "symbolic_file = angr.SimFile(FILE_PATH, content=symbolic, size=LENGTH)",
        "state.fs.insert(FILE_PATH, symbolic_file)",
    ]


def build_angr_harness(spec: SymbolicSpec | Mapping[str, object]) -> str:
    """Return deterministic Python source; no artifact is opened or executed."""
    value = normalize_spec(spec)
    main_options: dict[str, object] = {}
    if value.blob_arch is not None:
        main_options.update({
            "backend": "blob",
            "arch": _BLOB_ARCHES[value.blob_arch],
            "base_addr": value.base_addr,
            "entry_point": value.entry_addr,
        })
    elif value.base_addr is not None:
        main_options["base_addr"] = value.base_addr
    project_kwargs = {"auto_load_libs": False}
    if main_options:
        project_kwargs["main_opts"] = main_options

    lines = [
        "#!/usr/bin/env python3",
        '"""Generated source: run only inside the CSCTF networkless Docker sandbox."""',
        "import json",
        "import angr",
        "import claripy",
        f"BINARY = {value.binary!r}",
        f"FILE_PATH = {value.file_path!r}",
        f"LENGTH = {value.length}",
        f"FIND = {value.find!r}",
        f"AVOID = {value.avoid!r}",
        f"ALPHABET = {value.alphabet!r}",
        f"MAX_STEPS = {value.max_steps}",
        f"MAX_ACTIVE = {value.max_active}",
        f"SOLUTION_LIMIT = {value.solution_limit}",
        f"project = angr.Project(BINARY, **{project_kwargs!r})",
        "symbolic = claripy.BVS('r5d_candidate', LENGTH * 8)",
    ]
    lines.extend(_state_lines(value))
    if value.zero_fill:
        lines.extend([
            "state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)",
            "state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)",
        ])
    fixed: dict[int, int] = {}
    fixed.update({index: byte for index, byte in enumerate(value.prefix)})
    suffix_at = value.length - len(value.suffix)
    fixed.update({suffix_at + index: byte for index, byte in enumerate(value.suffix)})
    for index, byte in sorted(fixed.items()):
        lines.append(f"state.solver.add(symbolic.get_byte({index}) == {byte})")
    free_indexes = [index for index in range(value.length) if index not in fixed]
    if value.alphabet == tuple(range(0x20, 0x7F)):
        for index in free_indexes:
            lines.append(
                f"state.solver.add(symbolic.get_byte({index}) >= 0x20, "
                f"symbolic.get_byte({index}) <= 0x7e)"
            )
    elif value.alphabet != tuple(range(256)):
        for index in free_indexes:
            lines.append(
                f"state.solver.add(claripy.Or(*[symbolic.get_byte({index}) == byte for byte in ALPHABET]))"
            )
    lines.extend([
        "manager = project.factory.simgr(state)",
        "explorer = angr.exploration_techniques.Explorer(",
        "    find=lambda candidate: candidate.addr in FIND,",
        "    avoid=lambda candidate: candidate.addr in AVOID,",
        "    num_find=1,",
        ")",
        "manager.use_technique(explorer)",
        "steps = 0",
        "while manager.active and not manager.found and steps < MAX_STEPS:",
        "    manager.step()",
        "    steps += 1",
        "    if len(manager.active) > MAX_ACTIVE:",
        "        manager.stashes.setdefault('r5d_deferred', []).extend(manager.active[MAX_ACTIVE:])",
        "        manager.stashes['active'] = manager.active[:MAX_ACTIVE]",
        "candidates = []",
        "ambiguous = False",
        "for found_state in manager.found[:1]:",
        "    models = found_state.solver.eval_upto(symbolic, SOLUTION_LIMIT + 1, cast_to=bytes)",
        "    ambiguous = ambiguous or len(models) > SOLUTION_LIMIT",
        "    for model in models[:SOLUTION_LIMIT]:",
        "        if model not in candidates:",
        "            candidates.append(model)",
        "result = {",
        "    'active_states': len(manager.active),",
        "    'ambiguous': ambiguous,",
        "    'candidates_hex': [candidate.hex() for candidate in candidates],",
        "    'deferred_states': len(manager.stashes.get('r5d_deferred', [])),",
        "    'found_states': len(manager.found),",
        "    'steps': steps,",
        "}",
        "print(json.dumps(result, sort_keys=True))",
    ])
    source = "\n".join(lines) + "\n"
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("generated harness exceeds the 2 MiB source cap")
    return source


def _metadata_fields(report: object) -> tuple[str, str | None, bool]:
    metadata = getattr(report, "metadata", None)
    if metadata is None and isinstance(report, Mapping):
        metadata = report.get("metadata")
    if isinstance(metadata, Mapping):
        fmt = metadata.get("format")
        arch = metadata.get("architecture")
        managed = metadata.get("managed", False)
    else:
        fmt = getattr(metadata, "format", None)
        arch = getattr(metadata, "architecture", None)
        managed = getattr(metadata, "managed", False)
    if not isinstance(fmt, str) or arch is not None and not isinstance(arch, str) or not isinstance(managed, bool):
        raise ValueError("static report metadata is malformed")
    return fmt, arch, managed


def spec_from_static_report(
    report: object,
    *,
    binary: str,
    length: int,
    find: Sequence[int | str],
    avoid: Sequence[int | str] = (),
    mode: str = "stdin",
    **overrides: object,
) -> SymbolicSpec:
    """Build a native angr spec from header metadata and explicit solve goals.

    Managed JVM/.NET, WebAssembly, and eBPF inputs are rejected instead of
    silently generating a misleading native harness.
    """
    fmt, arch, managed = _metadata_fields(report)
    if managed:
        raise ValueError("managed artifacts need a VM-aware model, not this native angr harness")
    if fmt not in {"elf", "pe", "macho"}:
        raise ValueError(f"{fmt} is not supported by the native angr harness")
    if arch == "ebpf":
        raise ValueError("eBPF needs a verifier/interpreter-aware symbolic model")
    if arch is not None and arch not in _ARCH_HINTS:
        raise ValueError(f"unsupported native architecture: {arch}")
    if "architecture_hint" in overrides:
        raise ValueError("architecture_hint is derived from the static report")
    raw: dict[str, object] = {
        "binary": binary,
        "mode": mode,
        "length": length,
        "find": list(find),
        "avoid": list(avoid),
        "architecture_hint": arch,
    }
    raw.update(overrides)
    return SymbolicSpec.from_mapping(raw)


def build_harness_from_static_report(report: object, **kwargs: object) -> tuple[str, str]:
    """Return ``(source, canonical manifest)`` from a static report."""
    spec = spec_from_static_report(report, **kwargs)
    return build_angr_harness(spec), render_manifest(spec)


__all__ = [
    "SymbolicSpec", "normalize_spec", "render_manifest", "build_angr_harness",
    "spec_from_static_report", "build_harness_from_static_report",
]
