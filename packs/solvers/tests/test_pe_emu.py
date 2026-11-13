#!/usr/bin/env python3
"""Offline tests for the agent-only PE mapper and closed Unicorn policy.

Every executable byte below is a synthetic inert fixture built in this file.  The
test never reads, imports, or emulates a challenge delivery and never uses a native
subprocess or loader path.
"""
from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from solvers.toolkits import pe_emu as PE  # noqa: E402


def _mapped_pe():
    """The synthetic mapped PE shared by the harness tests (and the fixture below)."""
    raw, preferred = synthetic_pe()
    loaded = preferred + 0x200000
    return PE.map_pe(raw, load_base=loaded)


@pytest.fixture
def pe():
    return _mapped_pe()


CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(label)


def refused(function, contains):
    global CHECKS
    CHECKS += 1
    try:
        function()
    except (PE.PEError, PE.EmulationDenied) as exc:
        if contains not in str(exc):
            raise AssertionError(f"expected {contains!r}, got {exc!r}") from exc
    else:
        raise AssertionError(f"expected refusal containing {contains!r}")


def synthetic_pe(code=b"\x39\xd8\xc3", relocation_type=PE.IMAGE_REL_BASED_DIR64):
    """One PE32+ with .text, one KERNEL32 import and one DIR64 pointer."""
    preferred = 0x140000000
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, PE.IMAGE_FILE_MACHINE_AMD64, 3,
                     0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<Q", data, optional + 24, preferred)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", data, optional + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", data, optional + 52, 0, 0x4000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<QQQQ", data, optional + 72, 1 << 20, 0x1000, 1 << 20, 0x1000)
    struct.pack_into("<II", data, optional + 104, 0, 16)
    # Import and base-relocation directories.
    struct.pack_into("<II", data, optional + 112 + 8, 0x2000, 40)
    struct.pack_into("<II", data, optional + 112 + 5 * 8, 0x3000, 12)

    section_table = optional + 0xF0
    sections = (
        (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, 0x60000020),
        (b".idata\0\0", 0x200, 0x2000, 0x200, 0x400, 0xC0000040),
        (b".reloc\0\0", 0x200, 0x3000, 0x200, 0x600, 0x42000040),
    )
    for index, (name, vsize, rva, raw_size, raw_at, flags) in enumerate(sections):
        at = section_table + index * 40
        data[at:at + 8] = name
        struct.pack_into("<IIIIIIHHI", data, at + 8, vsize, rva, raw_size, raw_at,
                         0, 0, 0, 0, flags)
    data[0x200:0x200 + len(code)] = code

    idata = 0x400
    struct.pack_into("<IIIII", data, idata, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<Q", data, idata + 0x40, 0x2090)
    struct.pack_into("<Q", data, idata + 0x48, 0)
    struct.pack_into("<Q", data, idata + 0x60, 0x2090)
    struct.pack_into("<Q", data, idata + 0x68, 0)
    data[idata + 0x80:idata + 0x80 + 13] = b"KERNEL32.dll\0"
    data[idata + 0x90:idata + 0x90 + 15] = b"\0\0VirtualAlloc\0"
    struct.pack_into("<Q", data, idata + 0xB0, preferred + 0x1234)

    reloc = 0x600
    struct.pack_into("<IIHH", data, reloc, 0x2000, 12,
                     (relocation_type << 12) | 0xB0, 0)
    return bytes(data), preferred


class FakeX86:
    pass


_REG_NAMES = (
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "RFLAGS",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "FS_BASE", "GS_BASE",
    "MXCSR", "EAX", "EBX",
) + tuple(f"XMM{i}" for i in range(16))
for _index, _name in enumerate(_REG_NAMES, 1):
    setattr(FakeX86, "UC_X86_REG_" + _name, _index)
FakeX86.UC_X86_INS_SYSCALL = 1001
FakeX86.UC_X86_INS_SYSENTER = 1002


class FakeUc:
    def __init__(self, _arch, _mode):
        self.maps = []
        self.regs = {}
        self.hooks = []
        self.script = []
        self.stopped = False

    def mem_map(self, start, size, permissions):
        if any(start < old + len(data) and old < start + size for old, data, _ in self.maps):
            raise RuntimeError("overlap")
        self.maps.append((start, bytearray(size), permissions))

    def _where(self, address, size):
        for start, data, permissions in self.maps:
            if start <= address and size <= start + len(data) - address:
                return start, data, permissions
        raise RuntimeError(f"unmapped {address:#x}+{size}")

    def mem_write(self, address, raw):
        raw = bytes(raw)
        start, data, _ = self._where(address, len(raw))
        offset = address - start
        data[offset:offset + len(raw)] = raw

    def mem_read(self, address, size):
        start, data, _ = self._where(address, size)
        offset = address - start
        return bytes(data[offset:offset + size])

    def mem_protect(self, _address, _size, _permissions):
        # SafeUnicorn enforces its own exact region table; the fake retains one
        # backing allocation so snapshot behavior can be tested deterministically.
        return None

    def ctl_flush_tb(self):
        # The fake translates nothing; the harness still requires the call to exist (B-241).
        self.flushes = getattr(self, "flushes", 0) + 1

    def ctl_remove_cache(self, low, high):
        self.removed = getattr(self, "removed", []) + [(low, high)]

    def reg_write(self, register, value):
        self.regs[register] = int(value)

    def reg_read(self, register):
        return self.regs.get(register, 0)

    def hook_add(self, kind, callback, user_data=None, begin=1, end=0, aux1=0):
        self.hooks.append((kind, callback, user_data, begin, end, aux1))
        return len(self.hooks)

    def emu_stop(self):
        self.stopped = True

    def _dispatch(self, mask, *args, aux1=None):
        for kind, callback, user_data, _begin, _end, hook_aux in tuple(self.hooks):
            if kind & mask and (aux1 is None or not hook_aux or hook_aux == aux1):
                callback(self, *args, user_data)
                if self.stopped:
                    break

    def emu_start(self, _begin, _end, timeout=0, count=0):
        self.stopped = False
        for event in tuple(self.script):
            if self.stopped:
                break
            kind = event[0]
            if kind == "code":
                _, address, size = event
                self.regs[FakeX86.UC_X86_REG_RIP] = address
                self._dispatch(FakeModule.UC_HOOK_CODE, address, size)
            elif kind == "read":
                _, address, size = event
                self._dispatch(FakeModule.UC_HOOK_MEM_READ, FakeModule.UC_MEM_READ, address, size, 0)
            elif kind == "write":
                _, address, size, value = event
                self._dispatch(FakeModule.UC_HOOK_MEM_WRITE, FakeModule.UC_MEM_WRITE, address, size, value)
            elif kind == "unmapped":
                _, address, size = event
                self._dispatch(FakeModule.UC_HOOK_MEM_INVALID, FakeModule.UC_MEM_READ_UNMAPPED,
                               address, size, 0)
            elif kind == "interrupt":
                self._dispatch(FakeModule.UC_HOOK_INTR, event[1])
            elif kind == "invalid":
                self._dispatch(FakeModule.UC_HOOK_INSN_INVALID)
            elif kind == "syscall":
                self._dispatch(FakeModule.UC_HOOK_INSN, aux1=FakeX86.UC_X86_INS_SYSCALL)


class FakeModule:
    Uc = FakeUc
    UcError = RuntimeError
    UC_ARCH_X86 = 1
    UC_MODE_64 = 2
    UC_PROT_READ = 1
    UC_PROT_WRITE = 2
    UC_PROT_EXEC = 4
    UC_HOOK_CODE = 1 << 0
    UC_HOOK_MEM_READ = 1 << 1
    UC_HOOK_MEM_WRITE = 1 << 2
    UC_HOOK_MEM_INVALID = 1 << 3
    UC_HOOK_INTR = 1 << 4
    UC_HOOK_INSN_INVALID = 1 << 5
    UC_HOOK_INSN = 1 << 6
    UC_MEM_READ = 16
    UC_MEM_WRITE = 17
    UC_MEM_READ_UNMAPPED = 19
    UC_MEM_WRITE_UNMAPPED = 20
    UC_MEM_WRITE_PROT = 22


BACKEND = SimpleNamespace(uc=FakeModule, x86=FakeX86)


def harness(pe, **kwargs):
    return PE.SafeUnicorn(pe, backend=BACKEND, **kwargs)


def test_mapping_and_hashes():
    raw, preferred = synthetic_pe()
    loaded = preferred + 0x200000
    pe = PE.map_pe(raw, load_base=loaded)
    check(pe.load_base == loaded and pe.entry == loaded + 0x1000, "mapped entry/base")
    check(struct.unpack_from("<Q", pe.image, 0x20B0)[0] == loaded + 0x1234,
          "DIR64 relocation applies the exact base delta")
    check(len(pe.relocations) == 1 and pe.relocations[0].rva == 0x20B0,
          "relocation evidence is retained")
    check(len(pe.imports) == 1 and pe.imports[0].display == "kernel32.dll!VirtualAlloc",
          "bounded import table resolves DLL and export")
    check(pe.imports[0].iat_rva == 0x2060, "IAT RVA retained")
    check(pe.rva_bytes(0x1000, 3) == b"\x39\xd8\xc3", "section bytes mapped")
    signed = bytearray(raw + bytes(0x200))
    optional = 0x98
    struct.pack_into("<II", signed, optional + 112 + PE.IMAGE_DIRECTORY_ENTRY_SECURITY * 8,
                     0x800, 0x20)
    signed_pe = PE.map_pe(signed, load_base=loaded)
    check(signed_pe.directory(PE.IMAGE_DIRECTORY_ENTRY_SECURITY).rva == 0x800,
          "certificate file-offset directory is bounded without treating it as an RVA")
    refused(lambda: PE.map_pe(raw[:-1], load_base=loaded), "raw bytes")
    bad, _ = synthetic_pe(relocation_type=5)
    refused(lambda: PE.map_pe(bad), "unsupported relocation type")

    check(PE.hash_ror13("LoadLibraryA") == 0xEC0E4E8E, "known ROR13 LoadLibraryA hash")
    check(PE.hash_ror13("GetProcAddress") == 0x7C0DFCAA, "known ROR13 GetProcAddress hash")
    matches = PE.resolve_api_hash(0x91AFCA54)
    check(any(row.algorithm == "ror13" and row.display == "kernel32.dll!VirtualAlloc" for row in matches),
          "common API-hash resolution")
    colliding = PE.build_api_hash_index(["One", "Two"], {"all": lambda _name: 7})[7]
    check([row.name for row in colliding] == ["One", "Two"], "hash collisions remain explicit")
    check(PE.resolve_api_hash(0xDEADBEEF, ["VirtualAlloc"]) == (), "unknown hash remains unknown")


def test_compare_and_closed_harness(pe):
    sites = PE.find_compare_sites(pe)
    check(len(sites) == 1 and sites[0].mnemonic == "cmp", "compare-site discovery")
    check(sites[0].rva == 0x1000 and sites[0].encoding == b"\x39\xd8", "compare-site RVA/bytes")

    box = harness(pe)
    check(len(box.import_stubs) == 1, "every import receives one deny stub")
    imported_stub = next(iter(box.import_stubs.values()))
    box.uc.script = [("code", imported_stub, 1)]
    refused(lambda: box.run(imported_stub), "import/API call denied")

    syscall_raw, preferred = synthetic_pe(b"\x0f\x05\xc3")
    syscall_pe = PE.map_pe(syscall_raw, load_base=preferred + 0x400000)
    sysbox = harness(syscall_pe)
    sysbox.uc.script = [("code", syscall_pe.entry, 2)]
    refused(lambda: sysbox.run(syscall_pe.entry), "system/environment instruction denied: syscall")

    for event, word in ((("interrupt", 3), "software interrupt denied"),
                        (("unmapped", 0xDEAD0000, 8), "unmapped/protection"),
                        (("invalid",), "invalid instruction denied"),
                        (("syscall",), "syscall/sysenter denied")):
        guarded = harness(pe)
        guarded.uc.script = [event]
        refused(lambda guarded=guarded: guarded.run(pe.entry), word)

    undefined = harness(pe)
    undefined.uc.script = [("read", undefined.stack_base, 8)]
    refused(lambda: undefined.run(pe.entry), "undefined memory")

    capped = harness(pe, instruction_cap=2)
    capped.uc.script = [("code", pe.entry, 2), ("code", pe.entry, 2), ("code", pe.entry, 2)]
    refused(lambda: capped.run(pe.entry), "instruction budget exceeded")

    class StepClock:
        def __init__(self):
            self.value = -1.0

        def __call__(self):
            self.value += 1.0
            return self.value

    timed = harness(pe, wall_seconds=0.5, clock=StepClock())
    timed.uc.script = [("code", pe.entry, 2)]
    refused(lambda: timed.run(pe.entry), "wall-time budget exceeded")

    stopped = harness(pe)
    stopped.uc.script = [("code", sites[0].address, sites[0].size)]
    result = stopped.run(pe.entry, stop_addresses=[sites[0].address])
    check(result.reason == "site" and result.address == sites[0].address,
          "only an approved stop is a result")
    stopped.uc.reg_write(FakeX86.UC_X86_REG_EAX, 0x11223344)
    stopped.uc.reg_write(FakeX86.UC_X86_REG_EBX, 0x55667788)
    operands = stopped.observe_compare(sites[0])
    check([row.value for row in operands] == [0x11223344, 0x55667788],
          "compare operand observation")


def test_snapshots_and_source(pe):
    original = harness(pe)
    original.write_memory(original.scratch_base + 0x20, b"parent")
    original.write_register("rax", 0x1111)
    snap = original.snapshot()
    child = original.fork(snap)
    child.write_memory(child.scratch_base + 0x20, b"child!")
    child.write_register("rax", 0x2222)
    check(original.read_memory(original.scratch_base + 0x20, 6) == b"parent",
          "fork memory is isolated")
    check(original.read_register("rax") == 0x1111 and child.read_register("rax") == 0x2222,
          "fork registers are isolated")
    restored = original.fork(child.snapshot())
    check(restored.read_memory(restored.scratch_base + 0x20, 6) == b"child!",
          "immutable snapshot restores exact bytes")
    check(snap.memory != child.snapshot().memory, "parent snapshot does not alias child state")

    other_raw, other_base = synthetic_pe(b"\x85\xc0\xc3")
    other = harness(PE.map_pe(other_raw, load_base=other_base + 0x600000))
    refused(lambda: other.restore(snap), "different mapped PE")
    refused(lambda: original.read_memory(original.scratch_base + 0x100, 1), "defined emulated memory")

    source_path = ROOT / "solvers" / "toolkits" / "pe_emu.py"
    source = source_path.read_text()
    tree = ast.parse(source)
    imports = {alias.name.split(".", 1)[0]
               for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imports |= {str(node.module).split(".", 1)[0]
                for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    check(not imports.intersection({"subprocess", "ctypes", "mmap", "multiprocessing"}),
          "module has no native subprocess/loader imports")
    called_names = {node.func.attr for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    check(not called_names.intersection({"system", "popen", "dlopen", "LoadLibrary", "CDLL"}),
          "module has no native execution/loader call path")
    check("def solve_set" not in source and "def signals" not in source,
          "hand tool cannot become a matcher or emit solver answers")


def main():
    test_mapping_and_hashes()
    pe = _mapped_pe()
    test_compare_and_closed_harness(pe)
    test_snapshots_and_source(pe)
    print(f"test_pe_emu: {CHECKS} checks pass (bounded PE/relocs, hashes, deny hooks/caps, snapshots, no native path)")


if __name__ == "__main__":
    main()
