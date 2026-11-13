#!/usr/bin/env python3
"""Offline tests for the Windows process-model layer of the PE harness (B-148).

Every fixture here is synthetic and inert: a hand-built PE, a hand-built LZNT1 blob, and a
dict-backed fake machine.  The modelled Windows behaviours are exercised through the abstract
:class:`pe_win.Machine` interface, so no native engine runs.  The handful of checks that drive
the real ``SafeUnicorn`` do so through the same in-repo ``FakeUc`` the base harness tests use
(``tests/test_pe_emu.py``); none touches a native Unicorn.  A real-Unicorn integration path is
a human step (see docs/build-log/B-148.md): it is behind the Darwin/arm64 guard in
``solvers/common/native_emulate`` and is marked ``needs_tool("py:unicorn")`` where present.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from solvers.toolkits import pe_emu as PE  # noqa: E402
# The Windows process model (B-148) lives in pe_emu itself; W is an alias for the same module so the
# two groups of checks below stay visually separate (PE.* for the mapper/harness, W.* for the model).
W = PE
from test_pe_emu import BACKEND  # noqa: E402  (the in-repo fail-closed sandbox fake)


# ------------------------------------------------------------------ synthetic PE builder
def build_pe(import_name: str = "VirtualAlloc", code: bytes = b"\x39\xd8\xc3\x90\x90\xc3",
             *, with_tls: bool = False):
    """One PE32+ with a single named import and (optionally) a TLS directory + callback.

    Mirrors the layout the base harness test uses, parameterised so a test can import a
    modelled API by name or attach a TLS callback that points at ``.text``.
    """
    preferred = 0x140000000
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, PE.IMAGE_FILE_MACHINE_AMD64, 3, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)          # entry RVA
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<Q", data, optional + 24, preferred)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", data, optional + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", data, optional + 52, 0, 0x4000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<QQQQ", data, optional + 72, 1 << 20, 0x1000, 1 << 20, 0x1000)
    struct.pack_into("<II", data, optional + 104, 0, 16)
    # Import and base-relocation data directories.
    struct.pack_into("<II", data, optional + 112 + 8, 0x2000, 40)
    struct.pack_into("<II", data, optional + 112 + 5 * 8, 0x3000, 12)
    if with_tls:
        struct.pack_into("<II", data, optional + 112 + 9 * 8, 0x2100, 40)   # TLS directory

    section_table = optional + 0xF0
    sections = (
        (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, 0x60000020),
        (b".idata\0\0", 0x200, 0x2000, 0x200, 0x400, 0xC0000040),
        (b".reloc\0\0", 0x200, 0x3000, 0x200, 0x600, 0x42000040),
    )
    for index, (name, vsize, rva, raw_size, raw_at, flags) in enumerate(sections):
        at = section_table + index * 40
        data[at:at + 8] = name
        struct.pack_into("<IIIIIIHHI", data, at + 8, vsize, rva, raw_size, raw_at, 0, 0, 0, 0, flags)
    data[0x200:0x200 + len(code)] = code

    idata = 0x400
    struct.pack_into("<IIIII", data, idata, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<Q", data, idata + 0x40, 0x2090)
    struct.pack_into("<Q", data, idata + 0x48, 0)
    struct.pack_into("<Q", data, idata + 0x60, 0x2090)
    struct.pack_into("<Q", data, idata + 0x68, 0)
    data[idata + 0x80:idata + 0x80 + 13] = b"KERNEL32.dll\0"
    name_bytes = b"\0\0" + import_name.encode() + b"\0"
    data[idata + 0x90:idata + 0x90 + len(name_bytes)] = name_bytes
    struct.pack_into("<Q", data, idata + 0xB0, preferred + 0x1234)

    if with_tls:
        # TLS directory struct at RVA 0x2100 (idata raw 0x500); callback array at 0x2120; index at 0x2140.
        struct.pack_into("<QQQQ", data, idata + 0x100, 0, 0,
                         preferred + 0x2140, preferred + 0x2120)
        struct.pack_into("<II", data, idata + 0x100 + 32, 0, 0)
        struct.pack_into("<QQ", data, idata + 0x120, preferred + 0x1000, 0)   # one callback -> .text

    reloc = 0x600
    struct.pack_into("<IIHH", data, reloc, 0x2000, 12,
                     (PE.IMAGE_REL_BASED_DIR64 << 12) | 0xB0, 0)
    return bytes(data), preferred


MASK64 = (1 << 64) - 1


# ------------------------------------------------------------------ dict-backed fake machine
class DictMachine:
    """A flat-memory :class:`pe_win.Machine` for testing the Windows model without an emulator."""

    SIZE = 0x400000

    def __init__(self):
        self.mem = bytearray(self.SIZE)
        self.regs: dict[str, int] = {}
        self._heap = 0x100000
        self.veh = W.VehChain()

    def read(self, address, size):
        assert 0 <= address and address + size <= self.SIZE, (address, size)
        return bytes(self.mem[address:address + size])

    def write(self, address, data):
        data = bytes(data)
        assert 0 <= address and address + len(data) <= self.SIZE, (address, len(data))
        self.mem[address:address + len(data)] = data

    def reg(self, name):
        return self.regs.get(name, 0)

    def setreg(self, name, value):
        self.regs[name] = int(value) & MASK64

    def alloc(self, size):
        if size <= 0:
            return 0
        base = self._heap
        nxt = base + ((size + 0xFFF) & ~0xFFF)
        if nxt > self.SIZE:
            return 0
        self._heap = nxt
        return base

    def add_veh(self, first, handler):
        return self.veh.add(first, handler)

    def remove_veh(self, cookie):
        return self.veh.remove(cookie)

    def set_args(self, *values, rsp=0x3000):
        """Place integer args per the Windows x64 ABI (rcx/rdx/r8/r9, then the stack)."""
        self.regs["rsp"] = rsp
        order = ("rcx", "rdx", "r8", "r9")
        for i, value in enumerate(values):
            if i < 4:
                self.regs[order[i]] = value & MASK64
            else:
                self.write(rsp + 8 + 8 * i, struct.pack("<Q", value & MASK64))


def _sym(name):
    return PE.ImportSymbol("kernel32.dll", name, None, 0x2060)


# ============================================================ LZNT1
def test_lznt1_known_vectors_and_roundtrip():
    # A stored (uncompressed) chunk: header 0x3004 then "hello".
    assert W.lznt1_decompress(b"\x04\x30hello") == b"hello"
    # A compressed chunk hand-derived in docs/build-log/B-148.md: one literal space then a
    # length-3 / displacement-1 phrase token, so four spaces decompress from six bytes.
    assert W.lznt1_decompress(b"\x03\xb0\x02\x20\x00\x00") == b"    "
    # Round-trips through the stored-chunk encoder across chunk boundaries.
    for n in (0, 1, 5, 4095, 4096, 4097, 9000):
        blob = bytes((i * 31 + 7) & 0xFF for i in range(n))
        assert W.lznt1_decompress(W.lznt1_compress_stored(blob)) == blob
    # Malformed streams fail closed rather than guessing.
    with pytest.raises(W.Lznt1Error):
        W.lznt1_decompress(b"\x00\x40aa")                # signature bits not 0b011
    with pytest.raises(W.Lznt1Error):
        W.lznt1_decompress(b"\x10\x30a")                 # chunk runs past the input
    with pytest.raises(W.Lznt1Error):
        W.lznt1_decompress(b"\x02\xb0\x02\x00")          # truncated phrase token


def test_lznt1_backreference_split_boundary():
    # Build a repetitive payload long enough to force the (length, displacement) split to widen,
    # then confirm the stored-encoder round-trip still reconstructs it exactly.
    payload = (b"ABCD" * 20) + bytes(range(64)) + (b"ZZ" * 50)
    assert W.lznt1_decompress(W.lznt1_compress_stored(payload)) == payload


def test_lznt1_phrase_token_widens_past_16_bytes():
    # A hand-built COMPRESSED chunk whose phrase token fires after the 17th decoded byte, so the
    # (length, displacement) split must widen once (pos >= 0x10): offset_shift 12 -> 11, length_mask
    # 0x0FFF -> 0x07FF.  The stored-chunk encoder never emits phrase tokens, so only a vector like
    # this exercises the widening loop at all.
    #
    # 17 literals ("0123456789ABCDEF" + "X") then phrase 0x8001.  With the widened split
    # (shift 11) that decodes as length 4 / displacement 17 -> copy "0123" from the start.
    # Without the widening (the mutant that keeps shift 12) the SAME two bytes decode as
    # length 4 / displacement 9 -> "89AB", a different and wrong answer -- which is what makes
    # this vector kill a mutation of the `while pos >= 0x10` threshold.
    chunk = b"\x00" + b"01234567" + b"\x00" + b"89ABCDEF" + b"\x02" + b"X" + b"\x01\x80"
    header = struct.pack("<H", 0x8000 | 0x3000 | (len(chunk) - 1))
    assert W.lznt1_decompress(header + chunk) == b"0123456789ABCDEFX0123"


# ============================================================ VehChain
def test_veh_chain_order_remove_and_dispatch():
    chain = W.VehChain()
    first = chain.add(False, 0x1000)
    chain.add(False, 0x2000)
    head = chain.add(True, 0x3000)                       # add-first goes to the front
    assert chain.handlers() == (0x3000, 0x1000, 0x2000)
    assert chain.remove(first) and chain.handlers() == (0x3000, 0x2000)
    assert not chain.remove(first)                       # removing a stale cookie is a no-op

    # Dispatch stops at the first handler that returns CONTINUE_EXECUTION.
    visited = []

    def verdict(handler):
        visited.append(handler)
        return (W.VehChain.EXCEPTION_CONTINUE_EXECUTION if handler == 0x2000
                else W.VehChain.EXCEPTION_CONTINUE_SEARCH)

    assert chain.dispatch(verdict) == 0x2000
    assert visited == [0x3000, 0x2000]
    # Every handler searching with no continue means the exception is unhandled.
    assert chain.dispatch(lambda _h: W.VehChain.EXCEPTION_CONTINUE_SEARCH) is None
    assert head != first


# ============================================================ WindowsEnvironment (pure)
def test_virtualalloc_heap_and_lasterror():
    env = W.WindowsEnvironment()
    m = DictMachine()
    m.set_args(0, 0x1000, 0x3000, 0x40)                  # VirtualAlloc(NULL, 0x1000, MEM_*, PAGE_*)
    env.VirtualAlloc(m)
    base = m.reg("rax")
    assert base and env.allocations[base] == 0x1000
    assert m.read(base, 0x1000) == b"\x00" * 0x1000      # VirtualAlloc hands back zeroed pages
    assert env.last_error == 0

    m.set_args(0x00A70000, W.HEAP_ZERO_MEMORY, 100)       # HeapAlloc(heap, HEAP_ZERO_MEMORY, 100)
    env.HeapAlloc(m)
    heap_block = m.reg("rax")
    assert heap_block and m.read(heap_block, 100) == b"\x00" * 100
    m.set_args(0x00A70000, 0, heap_block)                 # HeapSize(heap, 0, block)
    env.HeapSize(m)
    assert m.reg("rax") == 100
    m.set_args(0x00A70000, 0, 0xDEAD)                     # HeapSize of an unknown block -> (SIZE_T)-1
    env.HeapSize(m)
    assert m.reg("rax") == MASK64

    m.set_args(1234)                                      # SetLastError(1234)
    env.SetLastError(m)
    assert env.last_error == 1234
    env.GetLastError(m)
    assert m.reg("rax") == 1234


def test_rtldecompressbuffer_runs_lznt1():
    env = W.WindowsEnvironment()
    m = DictMachine()
    plain = b"the quick brown fox jumps over the lazy dog" * 4
    blob = W.lznt1_compress_stored(plain)
    dst, src, final = 0x1000, 0x40000, 0x80000
    m.write(src, blob)
    # RtlDecompressBuffer(LZNT1, dst, dst_size, src, src_size, final_ptr) with the last two on the stack.
    m.set_args(W.COMPRESSION_FORMAT_LZNT1, dst, len(plain) + 16, src, len(blob), final)
    env.RtlDecompressBuffer(m)
    assert m.reg("rax") == W.STATUS_SUCCESS
    assert m.read(dst, len(plain)) == plain
    assert struct.unpack("<I", m.read(final, 4))[0] == len(plain)

    # A non-LZNT1 format is reported unsupported, never silently decoded.
    m.set_args(1, dst, 4096, src, len(blob), final)
    env.RtlDecompressBuffer(m)
    assert m.reg("rax") == W.STATUS_UNSUPPORTED_COMPRESSION


def test_ntquery_debug_classes_and_anti_debug_log():
    env = W.WindowsEnvironment()
    m = DictMachine()
    buf, retlen = 0x1000, 0x2000
    m.set_args(0xFFFFFFFF, W.PROCESS_DEBUG_PORT, buf, 8, retlen)
    env.NtQueryInformationProcess(m)
    assert m.reg("rax") == W.STATUS_SUCCESS
    assert struct.unpack("<Q", m.read(buf, 8))[0] == 0           # no debug port
    assert struct.unpack("<I", m.read(retlen, 4))[0] == 8

    m.set_args(0xFFFFFFFF, W.PROCESS_DEBUG_OBJECT_HANDLE, buf, 8, retlen)
    env.NtQueryInformationProcess(m)
    assert m.reg("rax") == W.STATUS_PORT_NOT_SET                 # the NtQuery anti-debug tell

    m.set_args(W.SYSTEM_KERNEL_DEBUGGER_INFORMATION, buf, 2, retlen)
    env.NtQuerySystemInformation(m)
    assert m.read(buf, 2) == bytes((0, 1))                      # DebuggerEnabled=0, NotPresent=1

    env.IsDebuggerPresent(m)
    assert m.reg("rax") == 0
    m.set_args(0xFFFFFFFF, buf)
    env.CheckRemoteDebuggerPresent(m)
    assert struct.unpack("<I", m.read(buf, 4))[0] == 0

    probes = {event.query for event in env.anti_debug}
    assert {"ProcessDebugPort", "ProcessDebugObjectHandle", "SystemKernelDebuggerInformation",
            "PEB.BeingDebugged", "DebugPort"} <= probes


def test_dynamic_api_resolution_is_recorded():
    env = W.WindowsEnvironment()
    m = DictMachine()
    m.write(0x25000, b"ole32.dll\x00")
    m.write(0x25100, b"CoCreateInstance\x00")               # HIWORD != 0: a name, not an ordinal
    m.set_args(0x25000)
    env.LoadLibraryA(m)
    module = m.reg("rax")
    assert module and env.loaded_modules["ole32.dll"] == module
    m.set_args(module, 0x25100)
    env.GetProcAddress(m)
    assert m.reg("rax") != 0                                     # a resolvable pseudo-address
    assert ("ole32.dll", "CoCreateInstance") in env.resolved


def test_veh_registration_through_environment():
    env = W.WindowsEnvironment()
    m = DictMachine()
    m.set_args(0, 0x401000)                                      # RtlAddVectoredExceptionHandler(0, h)
    env.RtlAddVectoredExceptionHandler(m)
    cookie = m.reg("rax")
    assert cookie and m.veh.handlers() == (0x401000,)
    m.set_args(cookie)
    env.RtlRemoveVectoredExceptionHandler(m)
    assert m.reg("rax") == 1 and len(m.veh) == 0


def test_handles_rejects_unmodelled_and_ordinal_imports():
    env = W.WindowsEnvironment()
    assert env.handles(_sym("VirtualAlloc"))
    assert not env.handles(_sym("CreateFileW"))                 # not modelled -> harness denies it
    assert not env.handles(PE.ImportSymbol("kernel32.dll", None, 7, 0x2060))   # ordinal-only
    assert "virtualalloc" in W.modelled_apis() and "rtldecompressbuffer" in W.modelled_apis()


# ============================================================ TLS parsing
def test_parse_tls_directory():
    raw, preferred = build_pe(with_tls=True)
    pe = PE.map_pe(raw)                                          # map at the preferred base (no rebase)
    assert pe.load_base == preferred
    tls = W.parse_tls(pe)
    assert tls.callbacks == (preferred + 0x1000,)               # the one callback -> .text entry
    assert tls.index_address == preferred + 0x2140

    # A PE without a TLS directory yields no callbacks.
    raw2, _ = build_pe(with_tls=False)
    assert W.parse_tls(PE.map_pe(raw2)).callbacks == ()


# ============================================================ verified answer selection
def test_verify_candidates_rejects_printable_decoy(tmp_path):
    from shared_findings import FindingsBoard, digest_gate

    flag = "flag{sha1_hulud_real}"
    board = FindingsBoard(tmp_path / "findings.jsonl",
                          gate=digest_gate("sha256", hashlib.sha256(flag.encode()).hexdigest()))
    # A printable decoy that emulation might surface must never win over the gated answer.
    winner = W.verify_candidates(board, ["flag{printable_decoy}", flag, "flag{another_decoy}"],
                                 agent="b148-test")
    assert winner == flag
    assert [f.candidate for f in board.accepted()] == [flag]

    board2 = FindingsBoard(tmp_path / "decoy_only.jsonl",
                           gate=digest_gate("sha256", hashlib.sha256(flag.encode()).hexdigest()))
    assert W.verify_candidates(board2, ["flag{only_a_decoy}"], agent="b148-test") is None
    assert board2.accepted() == []


# ============================================================ SafeUnicorn integration (FakeUc)
def _harness(pe, **kwargs):
    return PE.SafeUnicorn(pe, backend=BACKEND, **kwargs)


def test_modelled_virtualalloc_through_harness():
    raw, preferred = build_pe(import_name="VirtualAlloc")
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    env = W.WindowsEnvironment()
    box = _harness(pe, environment=env)
    stub = next(stub for sym, stub in box.import_stubs.items() if sym.name == "VirtualAlloc")
    box.uc.script = [("code", stub, 1), ("code", box.return_sentinel, 1)]
    result = box.call(stub, args=(0, 0x2000, 0x3000, 0x40))
    assert result.reason == "return"
    base = box.read_register("rax")
    assert base == box.HEAP_BASE                                # served from the harness heap arena
    assert env.allocations[base] == 0x2000
    assert box.read_register("rip") == box.return_sentinel      # the modelled call simulated its ret


def test_modelled_isdebuggerpresent_logs_anti_debug():
    raw, preferred = build_pe(import_name="IsDebuggerPresent")
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    env = W.WindowsEnvironment()
    box = _harness(pe, environment=env)
    stub = next(stub for sym, stub in box.import_stubs.items() if sym.name == "IsDebuggerPresent")
    box.uc.script = [("code", stub, 1), ("code", box.return_sentinel, 1)]
    box.call(stub)
    assert box.read_register("rax") == 0                        # reports "no debugger"
    assert box.anti_debug_trace and box.anti_debug_trace[0].api == "IsDebuggerPresent"


def test_unmodelled_import_is_still_denied():
    raw, preferred = build_pe(import_name="CreateFileW")
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    box = _harness(pe, environment=W.WindowsEnvironment())
    stub = next(stub for sym, stub in box.import_stubs.items() if sym.name == "CreateFileW")
    box.uc.script = [("code", stub, 1)]
    with pytest.raises(PE.EmulationDenied) as exc:
        box.call(stub)
    assert "import/API call denied" in str(exc.value)


def test_run_tls_callbacks_through_harness():
    raw, preferred = build_pe(with_tls=True)
    pe = PE.map_pe(raw)                                         # preferred base: callback VA == RVA+base
    box = _harness(pe)
    callback = pe.load_base + 0x1000                           # the TLS callback points at .text
    box.uc.script = [("code", callback, 2), ("code", box.return_sentinel, 1)]
    results = box.run_tls_callbacks()
    assert len(results) == 1 and results[0].reason == "return"
    # rcx/rdx/r8 carried the TLS callback ABI (DllHandle, DLL_PROCESS_ATTACH, Reserved).
    assert box.read_register("rcx") == pe.load_base
    assert box.read_register("rdx") == 1


def test_veh_single_step_dispatch_through_harness():
    raw, preferred = build_pe()
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    box = _harness(pe, environment=W.WindowsEnvironment())
    handler = pe.load_base + 0x1003                             # a nop in .text
    assert box.add_veh(False, handler)
    start = pe.entry                                            # 0x1000: cmp eax,ebx (2 bytes)
    stop = pe.load_base + 0x1005
    box.uc.script = [
        ("code", start, 2),                                    # trap flag set -> deliver single step
        ("code", handler, 1),                                  # the VEH runs
        ("code", box.veh_trampoline, 1),                       # handler returns a verdict
        ("code", start, 2),                                    # execution resumes at the faulting insn
        ("code", stop, 1),                                     # an approved stop
    ]
    result = box.run(start, stop_addresses=[stop],
                     registers={"rflags": box.TRAP_FLAG,
                                "rax": box.EXCEPTION_CONTINUE_EXECUTION})
    assert box.single_step_trace == [start]                    # the step was recorded (anti-debug trace)
    assert box._state.get("veh_handled") == 1                  # the handler continued execution
    assert result.reason == "site" and result.address == stop
    # The trap flag was cleared on exception entry, so the resume did not re-dispatch.
    assert box.single_step_trace == [start]


def test_veh_handler_rewrites_context_rip_and_eflags():
    # The classic anti-debug VEH advances ContextRecord->Rip past junk (or decrypts via CONTEXT) and
    # returns CONTINUE_EXECUTION; the harness must resume from the handler-modified CONTEXT, not the
    # original fault.  Drive a handler that rewrites Rip and EFlags and confirm the resume honours it.
    raw, preferred = build_pe()
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    box = _harness(pe, environment=W.WindowsEnvironment())
    handler = pe.load_base + 0x1003
    assert box.add_veh(False, handler)
    start = pe.entry                                           # 0x1000: the trapped (faulting) insn
    skip_to = pe.load_base + 0x1005                            # where the handler redirects execution
    context_at = box.SCRATCH_BASE + 0x80
    captured: dict[str, int] = {}

    def anti_debug(_uc, address, _size, _user):
        if address == handler:                                 # the VEH body rewrites the CONTEXT
            box.write(context_at + box.CONTEXT_RIP_OFFSET, struct.pack("<Q", skip_to))
            box.write(context_at + box.CONTEXT_EFLAGS_OFFSET, struct.pack("<I", 0x1))  # set CF
        elif address == box.veh_trampoline:                    # snapshot the resume target _veh set
            captured["rip"] = box.read_register("rip")
            captured["rflags"] = box.read_register("rflags")

    box.uc.hook_add(BACKEND.uc.UC_HOOK_CODE, anti_debug)
    box.uc.script = [
        ("code", start, 2),                                    # trap -> deliver single step
        ("code", handler, 1),                                  # handler rewrites Rip/EFlags in CONTEXT
        ("code", box.veh_trampoline, 1),                       # handler returns CONTINUE_EXECUTION
        ("code", skip_to, 1),                                  # an approved stop at the new Rip
    ]
    result = box.run(start, stop_addresses=[skip_to],
                     registers={"rflags": box.TRAP_FLAG,
                                "rax": box.EXCEPTION_CONTINUE_EXECUTION})
    assert box._state.get("veh_handled") == 1
    # The resume used the handler's CONTEXT, not the original fault address (which was `start`).
    assert captured["rip"] == skip_to
    assert captured["rip"] != start
    assert captured["rflags"] & 0xFFFFFFFF == 0x1              # the handler's EFlags came back too
    assert result.reason == "site" and result.address == skip_to


def test_veh_continue_search_fans_out_and_preserves_context_through_harness():
    # Two VEHs in the chain: the first returns CONTINUE_SEARCH (after editing CONTEXT), the second
    # returns CONTINUE_EXECUTION.  The harness must run both handlers in order and carry the first
    # handler's CONTEXT edit through to the resume -- the CPU does not re-materialise CONTEXT between
    # chained handlers.  This drives the CONTINUE_SEARCH fan-out through SafeUnicorn, not just VehChain.
    raw, preferred = build_pe()
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)
    box = _harness(pe, environment=W.WindowsEnvironment())
    h1 = pe.load_base + 0x1003
    h2 = pe.load_base + 0x1004
    assert box.add_veh(False, h1) and box.add_veh(False, h2)    # add-last: dispatch order (h1, h2)
    start = pe.entry
    skip_to = pe.load_base + 0x1005
    context_at = box.SCRATCH_BASE + 0x80
    visited: list[int] = []
    captured: dict[str, int] = {}

    def chain(_uc, address, _size, _user):
        if address == h1:
            visited.append(h1)
            box.write(context_at + box.CONTEXT_RIP_OFFSET, struct.pack("<Q", skip_to))  # first edits
            box.write_register("rax", box.EXCEPTION_CONTINUE_SEARCH)                     # ... keep going
        elif address == h2:
            visited.append(h2)
            box.write_register("rax", box.EXCEPTION_CONTINUE_EXECUTION)                  # second handles
        elif address == box.veh_trampoline:
            captured["rip"] = box.read_register("rip")

    box.uc.hook_add(BACKEND.uc.UC_HOOK_CODE, chain)
    box.uc.script = [
        ("code", start, 2),                                    # trap -> deliver single step to h1
        ("code", h1, 1),                                       # h1 edits CONTEXT, returns SEARCH
        ("code", box.veh_trampoline, 1),                       # -> fan out to h2
        ("code", h2, 1),                                       # h2 returns EXECUTION
        ("code", box.veh_trampoline, 1),                       # -> resume from the (h1-edited) CONTEXT
        ("code", skip_to, 1),                                  # an approved stop
    ]
    result = box.run(start, stop_addresses=[skip_to],
                     registers={"rflags": box.TRAP_FLAG})
    assert visited == [h1, h2]                                 # both handlers ran, in chain order
    assert box._state.get("veh_handled") == 1
    # h1's CONTEXT.Rip edit survived the CONTINUE_SEARCH hand-off to h2 and drove the resume.
    assert captured["rip"] == skip_to
    assert result.reason == "site" and result.address == skip_to


@pytest.mark.needs_tool("py:unicorn", "py:capstone")
def test_real_unicorn_modelled_call_and_clean_return():
    # End-to-end against a real Unicorn backend where the platform allows it.  On Darwin/arm64
    # the engine declines when hw.cachelinesize is unreadable (native_emulate's guard); that is a
    # NOT RUN skip, never a silent pass.
    from solvers.common import native_emulate as ne
    if not ne.UNICORN_AVAILABLE:
        pytest.skip("not run: " + (ne.UNICORN_UNAVAILABLE_REASON
                                   or "Unicorn unavailable (Darwin/arm64 guard)"))
    raw, preferred = build_pe(import_name="VirtualAlloc", code=b"\xc3\x90\x90\x90\x90\xc3")
    pe = PE.map_pe(raw, load_base=preferred + 0x200000)

    # A modelled API call carried out inside real Unicorn: the code hook denies the int3 stub but
    # the environment answers instead, and the simulated ret lands on the sentinel.
    env = W.WindowsEnvironment()
    box = PE.SafeUnicorn(pe, environment=env)
    stub = next(s for sym, s in box.import_stubs.items() if sym.name == "VirtualAlloc")
    result = box.call(stub, args=(0, 0x3000, 0x3000, 0x40))
    assert result.reason == "return"
    base = box.read_register("rax")
    assert base == box.HEAP_BASE and env.allocations[base] == 0x3000

    # A genuine instruction executing in Unicorn: the entry `ret` pops the sentinel and stops.
    plain = PE.SafeUnicorn(pe)
    assert plain.run(pe.entry).reason == "return"

    # TLS callbacks run before entry, inside real Unicorn (the callback is a `cmp; ret`).
    tls_pe = PE.map_pe(build_pe(with_tls=True)[0])
    tls_box = PE.SafeUnicorn(tls_pe)
    tls_results = tls_box.run_tls_callbacks()
    assert len(tls_results) == 1 and tls_results[0].reason == "return"
