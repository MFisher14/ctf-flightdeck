#!/usr/bin/env python3
"""B-241: PE32 execution, the Win32 stdcall API layer, frame-based SEH, delay imports and dumps.

Every fixture is synthetic: a hand-built PE32 whose ``.text`` is the machine code of the listing
``tests/fixtures/native_image/B241_PE32.s`` (assembled by ``tests/b241_fixture_asm.py`` into
``tests/b241_blobs.py``; ``test_the_code_bytes_are_the_listing`` checks the decoding against capstone).  The execution tests drive the guarded real Unicorn
backend; they are marked ``needs_tool`` and skip with a named reason where the engine is unavailable, so
they report NOT RUN there, never green.  The Windows-model tests use a dict-backed 32-bit machine and need
no engine.
"""
from __future__ import annotations

import dataclasses
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "tests"))

from b241_blobs import PE32, PE32_LABELS  # noqa: E402
from solvers.common import native_emulate as NE  # noqa: E402
from solvers.toolkits import pe_emu as PE  # noqa: E402

BASE = 0x400000
TEXT = BASE + 0x1000
IAT = BASE + 0x2100            # IAT0, IAT1, ... of the listing
DIAT = BASE + 0x2180           # the delay-load IAT slot
DATA = BASE + 0x3000
PACKED = BASE + 0x4000

# The data cells the listing writes (all in .data, zero in the file).
D = {name: DATA + 4 * index for index, name in enumerate((
    "CODE", "ADDR", "FLAGS", "CTXFL", "SKIP", "COUNT", "DISP", "NPARAM", "INFO0", "INFO1", "OUTER",
    "VEH", "VEHDISP", "AB", "FRAME", "UWRET", "INNERFLAGS", "INNERUNW", "NREAD", "NWRIT", "OLD", "TLS"))}
D_BUF = DATA + 0x80

# Machine code of the listing tests/fixtures/native_image/B241_PE32.s (tests/b241_fixture_asm.py assembles it).
CODE = PE32
L = PE32_LABELS
A = {name: TEXT + offset for name, offset in L.items()}

# What the bytes are, entry by entry: (label, the mnemonics capstone must read from it, in order).
PE32_ASM = (
    ("add2", "mov add ret"),                                   # eax = [esp+4] + [esp+8]
    ("m_int3", "push push mov xor xor int3 pop add ret"),      # install `handler`, fault, uninstall
    ("m_ud2", "push push mov xor xor ud2 pop add ret"),
    ("m_hlt", "push push mov xor xor hlt pop add ret"),
    ("m_cli", "push push mov xor xor cli pop add ret"),
    ("m_div", "push push mov xor xor div pop add ret"),        # div ecx with ecx = 0
    ("m_wnull", "push push mov xor xor mov pop add ret"),      # mov [eax], eax with eax = 0
    ("m_rnull", "push push mov xor xor mov pop add ret"),      # mov eax, [eax] with eax = 0
    ("m_bare", "int3 ret"),
    ("m_step", "push push mov pushfd or popfd nop nop pop add ret"),
    ("peb_debugged", "mov movzx ret"),                         # fs:[0x30] -> byte [peb+2]
    ("teb_self", "mov ret"),                                   # fs:[0x18]
    ("peb_ldr", "mov mov ret"),                                # [peb+0xC]
    ("m_denied", "call ret"),
    ("m_delay", "push call call ret"),
    ("m_noprotect", "mov ret"),
    ("m_stub", "mov mov xor inc dec jne mov jmp"),
    ("tls_callback", "mov mov ret"),
)


def test_the_code_bytes_are_the_listing():
    capstone = pytest.importorskip("capstone")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for label, expected in PE32_ASM:
        want = expected.split()
        got = [ins.mnemonic for ins in decoder.disasm(CODE[L[label]:L[label] + 96], A[label])][:len(want)]
        assert got == want, (label, got)
    # the faulting instruction of each SEH entry sits where the label table says
    for label, first in (("m_int3_fault", b"\xcc"), ("m_ud2_fault", b"\x0f\x0b"), ("m_hlt_fault", b"\xf4"),
                         ("m_cli_fault", b"\xfa"), ("m_div_fault", b"\xf7\xf1"), ("m_wnull_fault", b"\x89\x00"),
                         ("m_rnull_fault", b"\x8b\x00"), ("m_two_fault", b"\xcc"), ("m_veh_fault", b"\xcc"),
                         ("m_abandon_fault", b"\xcc"), ("m_step_after", b"\x90")):
        assert CODE[L[label]:L[label] + len(first)] == first, label


# ------------------------------------------------------------------ the PE32 builder
PACKED_PLAIN = bytes.fromhex("b8ed5e0000c3")                  # mov eax, 0x5EED ; ret


def build_pe32(imports=("kernel32.dll", ()), delay=None, delay_attrs=1, tls=False, entry=0x1000):
    """A PE32 with .text (the listing), .idata, .data and a writable+executable .pack section.

    ``imports`` is ``(dll, names)``: its IAT is IAT0, IAT1, ... of the listing.  ``delay`` is
    ``(dll, name)`` for one delay-load import whose IAT slot is DIAT; ``delay_attrs`` 1 writes the
    descriptor with RVAs, 0 with VAs (the pre-VC7 form).  ``tls`` adds a TLS directory whose one callback
    is ``tls_callback``.
    """
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x44, PE.IMAGE_FILE_MACHINE_I386, 4, 0, 0, 0, 0xE0, 0x0103)
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<III", data, opt + 16, entry, 0x1000, 0x3000)
    struct.pack_into("<III", data, opt + 28, BASE, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", data, opt + 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<III", data, opt + 56, 0x5000, 0x200, 0)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<IIII", data, opt + 72, 1 << 20, 0x1000, 1 << 20, 0x1000)
    struct.pack_into("<II", data, opt + 88, 0, 16)
    directory = opt + 96
    sections = ((b".text", 0x1000, 0x800, 0x200, 0x60000020), (b".idata", 0x2000, 0x400, 0xA00, 0xC0000040),
                (b".data", 0x3000, 0x200, 0xE00, 0xC0000040), (b".pack", 0x4000, 0x200, 0x1000, 0xE0000020))
    for index, (name, rva, raw_size, raw_at, flags) in enumerate(sections):
        at = opt + 0xE0 + index * 40
        data[at:at + len(name)] = name
        struct.pack_into("<IIIIIIHHI", data, at + 8, 0x1000, rva, raw_size, raw_at, 0, 0, 0, 0, flags)
    data[0x200:0x200 + len(CODE)] = CODE
    data[0x1000:0x1000 + len(PACKED_PLAIN)] = bytes(b ^ 0x5A for b in PACKED_PLAIN)

    idata = 0xA00                                   # file offset of RVA 0x2000

    def put(rva, raw):
        data[idata + rva - 0x2000:idata + rva - 0x2000 + len(raw)] = raw

    strings = 0x2280

    def string(raw):
        nonlocal strings
        at = strings
        put(at, raw)
        strings += len(raw) + (len(raw) & 1)
        return at

    dll, names = imports
    if names:
        put(0x2000, struct.pack("<IIIII", 0x2040, 0, 0, string(dll.encode() + b"\0"), 0x2100))
        for index, name in enumerate(names):
            hint = string(b"\0\0" + name.encode() + b"\0")
            put(0x2040 + 4 * index, struct.pack("<I", hint))
            put(0x2100 + 4 * index, struct.pack("<I", hint))
        struct.pack_into("<II", data, directory + 8 * PE.IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 40)
    if delay:
        bias = 0 if delay_attrs else BASE
        ddll, dname = delay
        hint = string(b"\0\0" + dname.encode() + b"\0")
        put(0x21C0, struct.pack("<II", hint + bias, 0))                    # the delay name table
        put(0x2180, struct.pack("<II", A["m_bare"], 0))                    # the slot: the image's load thunk
        put(0x2200, struct.pack("<IIIIIIII", delay_attrs, string(ddll.encode() + b"\0") + bias,
                                0x21F0 + bias, 0x2180 + bias, 0x21C0 + bias, 0, 0, 0))
        struct.pack_into("<II", data, directory + 8 * PE.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2200, 64)
    if tls:
        put(0x2380, struct.pack("<IIIIII", 0, 0, BASE + 0x23B0, BASE + 0x23A0, 0, 0))
        put(0x23A0, struct.pack("<II", A["tls_callback"], 0))
        struct.pack_into("<II", data, directory + 8 * PE.IMAGE_DIRECTORY_ENTRY_TLS, 0x2380, 24)
    return bytes(data)


engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")


def sandbox(raw, environment=None, **kwargs):
    """The real 32-bit sandbox over ``raw`` (skips, named, where the guarded engine is unavailable)."""
    if not NE.UNICORN_AVAILABLE:
        pytest.skip(f"real Unicorn backend unavailable: {NE.UNICORN_UNAVAILABLE_REASON}")
    kwargs.setdefault("instruction_cap", 20_000)
    # wall_seconds is the harness's own ceiling, not what this test measures: the machine runs at a load
    # of 50-170, so the bound is the largest the harness accepts and the work is bounded by instructions
    kwargs.setdefault("wall_seconds", 60)
    return PE.SafeUnicorn(PE.map_pe(raw), environment=environment, **kwargs)


def cell(box, name):
    return int.from_bytes(box.read_memory(D[name], 4), "little")


def poke(box, name, value):
    box.write_memory(D[name], struct.pack("<I", value & 0xFFFFFFFF))


# ------------------------------------------------------------------ delay imports (parsing: no engine)
@pytest.mark.parametrize("attrs", [1, 0])
def test_delay_imports_are_parsed_in_both_descriptor_forms(attrs):
    raw = build_pe32(("kernel32.dll", ("VirtualAlloc", "SetLastError", "GetLastError")),
                     delay=("KERNEL32.dll", "SetLastError"), delay_attrs=attrs)
    pe = PE.map_pe(raw)
    assert [row.display for row in pe.delay_imports] == ["kernel32.dll!SetLastError"]
    assert pe.delay_imports[0].iat_rva == 0x2180
    # the mapper resolves nothing: the slot still holds the image's own load thunk
    assert struct.unpack_from("<I", pe.image, 0x2180)[0] == A["m_bare"]
    assert [row.display for row in pe.imports] == [
        "kernel32.dll!VirtualAlloc", "kernel32.dll!SetLastError", "kernel32.dll!GetLastError"]
    assert PE.ready_environment(raw, compare_sites=False).summary()["delay_imports"] == [
        "kernel32.dll!SetLastError"]


def test_delay_import_by_ordinal_and_malformed_descriptors():
    raw = bytearray(build_pe32(delay=("kernel32.dll", "SetLastError")))
    table = 0xA00 + 0x1C0
    struct.pack_into("<I", raw, table, 0x80000000 | 0x2A)                 # an ordinal thunk
    assert PE.map_pe(bytes(raw)).delay_imports[0].display == "kernel32.dll!#42"

    def broken(patch):
        bad = bytearray(build_pe32(delay=("kernel32.dll", "SetLastError")))
        patch(bad)
        with pytest.raises(PE.PEError) as error:
            PE.map_pe(bytes(bad))
        return str(error.value)

    descriptor = 0xA00 + 0x200
    assert "attributes" in broken(lambda b: struct.pack_into("<I", b, descriptor, 2))
    assert "no IAT or no name table" in broken(lambda b: struct.pack_into("<I", b, descriptor + 16, 0))
    assert "outside" in broken(lambda b: struct.pack_into("<I", b, descriptor + 12, 0x4FFE))
    assert "name" in broken(lambda b: struct.pack_into("<I", b, descriptor + 4, 0x4FFF))
    # the VA form exists for PE32 only: below the preferred base it is not an address of the image
    assert "below the preferred base" in broken(lambda b: struct.pack_into("<II", b, descriptor, 0, 0x2280))


def test_a_delay_slot_shared_with_a_regular_import_is_refused():
    raw = bytearray(build_pe32(("kernel32.dll", ("GetLastError",)), delay=("kernel32.dll", "SetLastError")))
    struct.pack_into("<I", raw, 0xA00 + 0x200 + 12, 0x2100)               # delay IAT -> the regular IAT slot
    with pytest.raises(PE.PEError, match="shared"):
        PE.map_pe(bytes(raw))


# ------------------------------------------------------------------ PE32 execution
@engine
def test_pe32_function_call_passes_stack_arguments_and_returns():
    box = sandbox(build_pe32())
    assert box.bits == 32 and box.pointer_bits == 32
    result = box.call(A["add2"], (5, 7))
    assert result.reason == "return" and result.address == box.return_sentinel
    assert box.read_register("eax") == 12
    box.call(A["add2"], (0xFFFFFFFF, 3))
    assert box.read_register("eax") == 2                                   # 32-bit wrap, not a 64-bit sum
    with pytest.raises(PE.EmulationDenied, match="unknown x86 register"):
        box.read_register("rax")


@engine
def test_pe32_modelled_stdcall_apis_run_and_clean_their_own_stack():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(("kernel32.dll", ("VirtualAlloc", "SetLastError", "GetLastError", "CreateFileA"))),
                  environment=env)
    result = box.call(A["m_api"])
    # the function returned to the sentinel: every stdcall API popped exactly its own arguments
    assert result.reason == "return"
    assert box.read_register("eax") == 0x57                                # GetLastError after SetLastError
    block = cell(box, "ADDR")
    assert block == box.HEAP_BASE and env.allocations == {block: 0x2000}
    assert cell(box, "CODE") == 0x41424344                                 # written to and read from the block
    assert env.last_error == 0x57


@engine
def test_pe32_unmodelled_import_is_denied_by_name():
    box = sandbox(build_pe32(("kernel32.dll", ("VirtualAlloc", "SetLastError", "GetLastError", "CreateFileA"))),
                  environment=PE.WindowsEnvironment())
    with pytest.raises(PE.EmulationDenied, match=r"import/API call denied: kernel32\.dll!CreateFileA"):
        box.call(A["m_denied"])


@engine
def test_pe32_delay_import_slot_reaches_the_modelled_api_when_bound():
    raw = build_pe32(("kernel32.dll", ("VirtualAlloc", "SetLastError", "GetLastError")),
                     delay=("kernel32.dll", "SetLastError"))
    env = PE.WindowsEnvironment()
    box = sandbox(raw, environment=env)
    slot = int.from_bytes(box.read_memory(DIAT, 4), "little")
    assert slot == box.import_stubs[box.pe.delay_imports[0]] and slot != A["m_bare"]
    assert box.call(A["m_delay"]).reason == "return"
    assert box.read_register("eax") == 0x58 and env.last_error == 0x58
    # unbound: the slot is the image's own thunk, as the mapper left it, and the stub table holds no entry
    plain = sandbox(raw, environment=PE.WindowsEnvironment(), bind_delay_imports=False)
    assert int.from_bytes(plain.read_memory(DIAT, 4), "little") == A["m_bare"]
    assert plain.pe.delay_imports[0] not in plain.import_stubs
    assert plain.fork().bind_delay_imports is False


@engine
def test_pe32_tls_callback_is_called_stdcall_with_the_reason():
    box = sandbox(build_pe32(tls=True))
    results = box.run_tls_callbacks(reason=1)
    assert [r.reason for r in results] == ["return"]
    assert cell(box, "TLS") == 1


# ------------------------------------------------------------------ x86 structured exceptions
FAULTS = [
    ("m_int3", PE.EXCEPTION_BREAKPOINT, 1, ()),
    ("m_ud2", PE.EXCEPTION_ILLEGAL_INSTRUCTION, 2, ()),
    ("m_hlt", PE.EXCEPTION_PRIV_INSTRUCTION, 1, ()),
    ("m_cli", PE.EXCEPTION_PRIV_INSTRUCTION, 1, ()),
    ("m_div", PE.EXCEPTION_INT_DIVIDE_BY_ZERO, 2, ()),
    ("m_wnull", PE.EXCEPTION_ACCESS_VIOLATION, 2, (1, 0)),               # a write to address 0
    ("m_rnull", PE.EXCEPTION_ACCESS_VIOLATION, 2, (0, 0)),               # a read of address 0
]


@engine
@pytest.mark.parametrize("entry,code,skip,info", FAULTS, ids=[row[0] for row in FAULTS])
def test_seh_handler_receives_the_exception_and_resumes_from_its_context(entry, code, skip, info):
    box = sandbox(build_pe32())
    poke(box, "SKIP", skip)                                                # the handler skips the instruction
    result = box.call(A[entry])
    assert result.reason == "return"
    fault = A[entry + "_fault"]
    assert cell(box, "COUNT") == 1
    assert cell(box, "CODE") == code and cell(box, "ADDR") == fault
    assert cell(box, "FLAGS") == 0                                         # continuable, not unwinding
    assert cell(box, "NPARAM") == len(info)
    if info:
        assert (cell(box, "INFO0"), cell(box, "INFO1")) == info
    assert box.read_register("eax") == 0x600D                              # CONTEXT.Eax was applied
    assert box.exception_trace == [(code, fault)]
    # the frame was unlinked by the function's own epilogue: the chain is empty again
    assert int.from_bytes(box.read_memory(box.TEB_BASE, 4), "little") == 0xFFFFFFFF


@engine
def test_an_exception_no_handler_continues_ends_the_run_by_name():
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match=r"unhandled exception 0x80000003 at 0x401200"):
        box.call(A["m_bare"])
    # a handler that answers ContinueSearch with nothing above it is unhandled as well
    box = sandbox(build_pe32())
    poke(box, "DISP", 1)
    with pytest.raises(PE.EmulationDenied, match="unhandled exception 0x80000003"):
        box.call(A["m_int3"])
    assert cell(box, "COUNT") == 1                                         # it was asked once


@engine
def test_seh_continue_search_walks_to_the_outer_frame():
    """The fault is two int3 in a row.  The inner handler moves CONTEXT.Eip on by one and answers
    ContinueSearch; the outer one moves it on by one more and continues.  Execution resumes past both
    only if the inner handler's CONTEXT edit was kept for the outer one: were it dropped, the second
    int3 would raise a second exception."""
    box = sandbox(build_pe32())
    assert CODE[L["m_two_fault"]:L["m_two_fault"] + 2] == b"\xcc\xcc"
    poke(box, "SKIP", 1)
    poke(box, "DISP", 1)                                                   # the inner handler declines
    assert box.call(A["m_two"]).reason == "return"
    assert cell(box, "COUNT") == 1 and cell(box, "OUTER") == 1             # inner asked once, then outer
    assert box.read_register("eax") == 0xBEEF                              # the outer handler's CONTEXT won
    assert box.exception_trace == [(PE.EXCEPTION_BREAKPOINT, A["m_two_fault"])]
    # with no skip neither handler moves Eip: the same int3 raises until the work budget ends the run
    box = sandbox(build_pe32())
    poke(box, "DISP", 1)
    with pytest.raises(PE.EmulationDenied, match="instruction budget exceeded"):
        box.call(A["m_two"], instruction_cap=2_000)
    assert cell(box, "COUNT") == cell(box, "OUTER") > 10


@engine
def test_single_step_trap_is_reported_after_the_stepped_instruction():
    box = sandbox(build_pe32())
    assert box.call(A["m_step"]).reason == "return"
    assert cell(box, "COUNT") == 1                                         # one trap, not one per instruction
    assert cell(box, "CODE") == PE.EXCEPTION_SINGLE_STEP
    assert cell(box, "ADDR") == A["m_step_after"]                          # the nop after popfd has run
    assert cell(box, "CTXFL") & box.TRAP_FLAG == 0                         # TF is clear in the reported frame


@engine
@pytest.mark.parametrize("verdict,eax,seh_calls", [(0xFFFFFFFF, 0x7E7, 0), (0, 0x600D, 1)])
def test_vectored_handlers_run_before_the_frame_chain(verdict, eax, seh_calls):
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(("kernel32.dll", ("AddVectoredExceptionHandler",))), environment=env)
    poke(box, "VEHDISP", verdict)
    poke(box, "SKIP", 1)
    assert box.call(A["m_veh"]).reason == "return"
    assert cell(box, "VEH") == 1 and cell(box, "COUNT") == seh_calls
    assert box.read_register("eax") == eax


@engine
def test_a_handler_that_abandons_the_dispatch_can_take_a_second_exception():
    box = sandbox(build_pe32())
    assert box.call(A["m_abandon"]).reason == "return"
    assert box.read_register("eax") == 2 and cell(box, "AB") == 2
    assert [code for code, _at in box.exception_trace] == [PE.EXCEPTION_BREAKPOINT] * 2


@engine
def test_an_exception_inside_a_handler_is_denied_as_nested():
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="nested dispatch is not modelled"):
        box.call(A["m_nested"])


@engine
def test_rtl_unwind_calls_the_inner_handler_unwinding_and_returns_to_its_caller():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(("ntdll.dll", ("RtlUnwind",))), environment=env)
    assert box.call(A["m_unwind"]).reason == "return"
    assert box.read_register("eax") == 0x77 and cell(box, "UWRET") == 0x77   # ReturnValue came back in EAX
    assert cell(box, "INNERUNW") == 1                                      # the inner frame was unwound once
    assert cell(box, "INNERFLAGS") & 2                                     # ... with EXCEPTION_UNWINDING set
    assert int.from_bytes(box.read_memory(box.TEB_BASE, 4), "little") == 0xFFFFFFFF
    # on the x86-64 model and outside a sandbox RtlUnwind stays unmodelled by name
    machine = Machine32()
    with pytest.raises(PE.WindowsModelError, match="RtlUnwind"):
        PE.WindowsEnvironment().dispatch(PE.ImportSymbol("ntdll.dll", "RtlUnwind", None, 0), machine)


@engine
def test_teb_and_peb_answer_only_their_modelled_fields():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(), environment=env)
    box.call(A["teb_self"])
    assert box.read_register("eax") == box.TEB_BASE
    box.call(A["peb_debugged"])
    assert box.read_register("eax") == 0
    assert [(e.api, e.query) for e in box.anti_debug_trace] == [("PEB", "BeingDebugged")]
    assert env.anti_debug == box.anti_debug_trace
    with pytest.raises(PE.EmulationDenied, match="undefined memory"):
        box.call(A["peb_ldr"])                                             # the loader data is not modelled


@engine
def test_virtual_protect_changes_image_protection_and_reports_the_old_one():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(("kernel32.dll", ("VirtualProtect",))), environment=env)
    assert box.call(A["m_protect"]).reason == "return"
    assert box.read_register("eax") == 0x2A                                # the patched immediate ran
    assert cell(box, "OLD") == 0x20                                        # .text was PAGE_EXECUTE_READ
    assert box.protect(TEXT, 0x1000, 0x20) == 0x40                         # and is PAGE_EXECUTE_READWRITE now
    assert box.protect(box.HEAP_BASE, 0x1000, 0x04) is None                # not image memory
    assert box.protect(TEXT, 0x1000, 0x777) == PE.PROTECT_FAILED
    # without the call the same write is an access violation on a read-only image page
    box = sandbox(build_pe32(("kernel32.dll", ("VirtualProtect",))), environment=PE.WindowsEnvironment())
    with pytest.raises(PE.EmulationDenied, match="unhandled exception 0xc0000005"):
        box.call(A["m_noprotect"])
    assert box.exception_trace == [(PE.EXCEPTION_ACCESS_VIOLATION, A["m_noprotect"])]


@engine
def test_standard_handles_capture_output_feed_input_and_exit_ends_the_run():
    env = PE.WindowsEnvironment(stdin=b"hello", command_line="crackme.exe key")
    names = ("GetStdHandle", "WriteFile", "ExitProcess", "ReadFile", "lstrlenA", "GetCommandLineA")
    box = sandbox(build_pe32(("kernel32.dll", names)), environment=env)
    result = box.call(A["m_io"])
    assert result.reason == "exit"
    assert bytes(env.stdout) == b"HELLO" and bytes(env.stderr) == b""
    assert cell(box, "NREAD") == 5 and cell(box, "NWRIT") == 5
    assert env.exit_code == len("crackme.exe key") == box.exit_code


# ------------------------------------------------------------------ write tracking and dumps
@engine
def test_run_stops_where_control_enters_written_bytes_and_the_dump_maps_again():
    raw = build_pe32(entry=0x1000 + L["m_stub"])
    env = PE.WindowsEnvironment()
    box = sandbox(raw, environment=env, track_image_writes=True)
    result = box.run(stop_on_written_exec=True)
    assert (result.reason, result.address) == ("written-exec", PACKED)
    assert bytes(box.image_written[0x4000:0x4006]) == b"\x01" * 6 and not any(box.image_written[:0x4000])
    memory = box.image_memory()
    assert memory[0x4000:0x4006] == PACKED_PLAIN
    dumped = PE.dump_pe(box.pe, memory, entry_rva=result.address - box.pe.load_base)
    again = PE.map_pe(dumped)
    assert again.entry_rva == 0x4000 and again.rva_bytes(0x4000, 6) == PACKED_PLAIN
    assert again.rva_bytes(0x1000, len(CODE)) == CODE                      # the rest of the image is intact
    assert [s.raw_offset for s in again.sections] == [0x1000, 0x2000, 0x3000, 0x4000]
    # the recovered code runs to its return from the recovered entry point
    assert box.run(result.address).reason == "return" and box.read_register("eax") == 0x5EED
    # without write tracking the stop is refused by name, and a plain run goes on into the payload
    plain = sandbox(raw)
    with pytest.raises(PE.EmulationDenied, match="write tracking is off"):
        plain.run(stop_on_written_exec=True)
    assert plain.run().reason == "return" and plain.read_register("eax") == 0x5EED


def test_dump_restores_the_import_slots_and_names_rebuilt_ones():
    raw = build_pe32(("kernel32.dll", ("GetLastError",)), delay=("kernel32.dll", "SetLastError"))
    pe = PE.map_pe(raw)
    memory = bytearray(pe.image)
    struct.pack_into("<I", memory, 0x2100, 0x50000000)                    # a sandbox stub in the IAT
    struct.pack_into("<I", memory, 0x2180, 0x50000010)                    # and in the delay IAT
    env = PE.WindowsEnvironment()
    env.resolved_addresses[0x7A000010] = ("user32.dll", "MessageBoxA")
    struct.pack_into("<I", memory, 0x3040, 0x7A000010)                    # a slot the stub rebuilt
    dumped = PE.dump_pe(pe, bytes(memory))
    assert dumped[0x2100:0x2104] == pe.image[0x2100:0x2104] != memory[0x2100:0x2104]
    assert dumped[0x2180:0x2184] == pe.image[0x2180:0x2184]
    assert PE.map_pe(dumped).entry_rva == pe.entry_rva                     # entry kept when none is given
    assert PE.rebuilt_imports(pe, bytes(memory), env) == ((0x3040, "user32.dll", "MessageBoxA"),)
    with pytest.raises(PE.PEError):
        PE.dump_pe(pe, bytes(memory)[:-1])
    with pytest.raises(PE.PEError):
        PE.dump_pe(pe, bytes(memory), entry_rva=0x5000)


@engine
def test_ready_environment_builds_the_32_bit_sandbox():
    if not NE.UNICORN_AVAILABLE:
        pytest.skip(f"real Unicorn backend unavailable: {NE.UNICORN_UNAVAILABLE_REASON}")
    setup = PE.ready_environment(build_pe32(tls=True))
    assert setup.pe.is_64 is False and setup.summary()["tls_callbacks"] == [hex(A["tls_callback"])]
    box = setup.sandbox(instruction_cap=5_000, wall_seconds=60)
    box.run_tls_callbacks()
    assert cell(box, "TLS") == 1


# ------------------------------------------------------------------ the Windows model on the x86 ABI
class Machine32:
    """A flat-memory 32-bit machine: stdcall arguments on the stack, results in EAX."""

    pointer_bits = 32
    SIZE = 0x200000

    def __init__(self):
        self.mem = bytearray(self.SIZE)
        self.regs = {"esp": 0x100000}
        self._heap = 0x180000
        self.load_base = 0x400000

    def read(self, address, size):
        assert 0 <= address and address + size <= self.SIZE, hex(address)
        return bytes(self.mem[address:address + size])

    def write(self, address, data):
        assert 0 <= address and address + len(data) <= self.SIZE, hex(address)
        self.mem[address:address + len(data)] = bytes(data)

    def reg(self, name):
        return self.regs[name]

    def setreg(self, name, value):
        self.regs[name] = value

    def alloc(self, size):
        base = self._heap
        self._heap += (size + 0xFFF) & ~0xFFF
        return base if self._heap <= self.SIZE else 0

    def args(self, *values):
        self.write(self.regs["esp"], struct.pack("<I", 0xDEAD) + b"".join(struct.pack("<I", v & 0xFFFFFFFF)
                                                                         for v in values))

    def call(self, env, name, *values):
        self.args(*values)
        env.dispatch(PE.ImportSymbol("kernel32.dll", name, None, 0), self)
        return self.regs.get("eax")


def test_api_arg_reads_the_x86_stack_and_results_go_to_eax():
    machine, env = Machine32(), PE.WindowsEnvironment()
    machine.args(11, 22, 33)
    assert [PE.api_arg(machine, i) for i in range(3)] == [11, 22, 33]
    assert PE.machine_bits(machine) == 32 and PE.machine_bits(object()) == 64
    with pytest.raises(PE.WindowsModelError):
        PE.api_arg(machine, -1)
    assert machine.call(env, "SetLastError", 0x1234) == 0 and "rax" not in machine.regs
    assert machine.call(env, "GetLastError") == 0x1234
    assert machine.call(env, "HeapSize", 0, 0, 0x5555) == 0xFFFFFFFF      # (SIZE_T)-1 at the machine's width
    assert machine.call(env, "GetCurrentProcess") == 0xFFFFFFFF
    assert machine.call(env, "GetCurrentThread") == 0xFFFFFFFE


def test_pointer_sized_answers_are_four_bytes_on_x86():
    machine, env = Machine32(), PE.WindowsEnvironment()
    machine.write(0x2000, b"\xEE" * 16)
    status = machine.call(env, "NtQueryInformationProcess", 0xFFFFFFFF, PE.PROCESS_DEBUG_PORT, 0x2000, 4, 0x2100)
    assert status == 0
    assert machine.read(0x2000, 8) == b"\x00" * 4 + b"\xEE" * 4            # four bytes written, not eight
    assert struct.unpack("<I", machine.read(0x2100, 4))[0] == 4
    module = machine.call(env, "LoadLibraryA", 0x3000)
    assert 0x79000000 <= module < 0x7A000000                               # a 32-bit pseudo handle
    machine.write(0x13100, b"MessageBoxA\0")                           # above 64 KiB: a name, not an ordinal
    proc = machine.call(env, "GetProcAddress", module, 0x13100)
    assert 0x7A000000 <= proc < 0x7B000000 and env.resolved_addresses[proc] == ("", "MessageBoxA")


def test_every_modelled_api_has_a_stdcall_argument_count():
    env = PE.WindowsEnvironment()
    for name in PE.modelled_apis():
        assert isinstance(env.stdcall_args(PE.ImportSymbol("x.dll", name, None, 0)), int), name
    assert env.stdcall_args(PE.ImportSymbol("x.dll", "CreateFileA", None, 0)) is None
    assert env.stdcall_args(PE.ImportSymbol("x.dll", None, 7, 0)) is None
    # spot values against the documented prototypes (a wrong count unbalances every x86 caller)
    for name, count in (("VirtualAlloc", 4), ("WriteFile", 5), ("RtlDecompressBuffer", 6),
                        ("GetProcAddress", 2), ("ExitProcess", 1), ("RtlUnwind", 4), ("GetLastError", 0)):
        assert env.stdcall_args(PE.ImportSymbol("x.dll", name, None, 0)) == count, name


def test_stream_string_and_memory_apis_on_the_model():
    machine, env = Machine32(), PE.WindowsEnvironment(stdin=b"abcdef")
    out = machine.call(env, "GetStdHandle", -11)
    err = machine.call(env, "GetStdHandle", -12)
    inp = machine.call(env, "GetStdHandle", -10)
    assert len({out, err, inp}) == 3
    assert machine.call(env, "GetStdHandle", -13) == 0xFFFFFFFF and env.last_error == 6
    machine.write(0x4000, b"flag?")
    assert machine.call(env, "WriteFile", out, 0x4000, 5, 0x4100, 0) == 1
    assert machine.call(env, "WriteConsoleA", err, 0x4000, 2, 0, 0) == 1
    assert bytes(env.stdout) == b"flag?" and bytes(env.stderr) == b"fl"
    assert struct.unpack("<I", machine.read(0x4100, 4))[0] == 5
    with pytest.raises(PE.WindowsModelError, match="only the standard output"):
        machine.call(env, "WriteFile", 0x1234, 0x4000, 5, 0, 0)
    with pytest.raises(PE.WindowsModelError, match="exceeds its cap"):
        machine.call(env, "WriteFile", out, 0x4000, PE.MAX_STREAM, 0, 0)
    assert machine.call(env, "ReadFile", inp, 0x5000, 4, 0x5100, 0) == 1
    assert machine.read(0x5000, 4) == b"abcd" and machine.read(0x5100, 4) == b"\x04\0\0\0"
    machine.call(env, "ReadFile", inp, 0x5000, 4, 0x5100, 0)
    assert machine.read(0x5000, 4) == b"efcd" and machine.read(0x5100, 4) == b"\x02\0\0\0"
    machine.call(env, "ReadFile", inp, 0x5000, 4, 0x5100, 0)
    assert machine.read(0x5100, 4) == b"\0\0\0\0"                          # end of input: zero bytes read
    with pytest.raises(PE.WindowsModelError, match="only the standard input"):
        machine.call(env, "ReadFile", out, 0x5000, 4, 0, 0)

    machine.write(0x6000, b"abc\0")
    machine.write(0x6100, "wide".encode("utf-16-le") + b"\0\0")
    assert machine.call(env, "lstrlenA", 0x6000) == 3 and machine.call(env, "lstrlenA", 0) == 0
    assert machine.call(env, "lstrlenW", 0x6100) == 4
    assert machine.call(env, "lstrcpyA", 0x6200, 0x6000) == 0x6200
    assert machine.call(env, "lstrcatA", 0x6200, 0x6000) == 0x6200
    assert machine.read(0x6200, 7) == b"abcabc\0"
    machine.call(env, "RtlFillMemory", 0x6300, 4, 0x41)
    machine.call(env, "RtlMoveMemory", 0x6302, 0x6000, 3)
    assert machine.read(0x6300, 6) == b"AAabc\0"
    machine.call(env, "RtlZeroMemory", 0x6300, 2)
    assert machine.read(0x6300, 5) == b"\0\0abc"
    with pytest.raises(PE.WindowsModelError, match="exceeds its cap"):
        machine.call(env, "RtlZeroMemory", 0x6300, PE.MAX_DECOMPRESSED + 1)

    first = machine.call(env, "GetCommandLineA")
    assert machine.read(first, 11) == b"sample.exe\0" and machine.call(env, "GetCommandLineA") == first
    wide = machine.call(env, "GetCommandLineW")
    assert wide != first and machine.read(wide, 22) == "sample.exe".encode("utf-16-le") + b"\0\0"
    with pytest.raises(PE.WindowsModelError, match="ExitProcess needs a sandbox"):
        machine.call(env, "ExitProcess", 3)
    assert env.exit_code == 3


def test_wide_module_names_are_read_as_utf16():
    machine, env = Machine32(), PE.WindowsEnvironment()
    machine.write(0x3000, "USER32.dll".encode("utf-16-le") + b"\0\0")
    handle = machine.call(env, "LoadLibraryW", 0x3000)
    assert env.loaded_modules == {"user32.dll": handle}
    assert machine.call(env, "GetModuleHandleW", 0x3000) == handle
    machine.write(0x3100, b"user32.dll\0")
    assert machine.call(env, "GetModuleHandleA", 0x3100) == handle
    assert machine.call(env, "GetModuleHandleA", 0) == machine.load_base


def test_virtual_protect_without_a_sandbox_keeps_its_plain_answer():
    machine, env = Machine32(), PE.WindowsEnvironment()
    assert machine.call(env, "VirtualProtect", 0x401000, 0x1000, 0x40, 0x7000) == 1
    assert struct.unpack("<I", machine.read(0x7000, 4))[0] == 0x40
    machine.protect = lambda address, size, protection: PE.PROTECT_FAILED
    assert machine.call(env, "VirtualProtect", 0x401000, 0x1000, 0x999, 0x7000) == 0 and env.last_error == 87
    machine.protect = lambda address, size, protection: 0x20 if (address, size, protection) == (
        0x401000, 0x1000, 0x40) else None
    assert machine.call(env, "VirtualProtect", 0x401000, 0x1000, 0x40, 0x7000) == 1
    assert struct.unpack("<I", machine.read(0x7000, 4))[0] == 0x20


def test_the_x86_64_abi_is_unchanged_for_the_new_apis():
    """The same handlers on a machine without ``pointer_bits``: Windows x64 registers, 64-bit answers."""
    class Machine64(Machine32):
        pointer_bits = 64

        def __init__(self):
            super().__init__()
            self.regs = {"rsp": 0x100000, "rcx": 0, "rdx": 0, "r8": 0, "r9": 0}

        def call(self, env, name, *values):
            for register, value in zip(("rcx", "rdx", "r8", "r9"), values):
                self.regs[register] = value & PE.MASK64
            for index, value in enumerate(values[4:]):
                self.write(0x100000 + 0x28 + 8 * index, struct.pack("<Q", value & PE.MASK64))
            env.dispatch(PE.ImportSymbol("kernel32.dll", name, None, 0), self)
            return self.regs.get("rax")

    machine, env = Machine64(), PE.WindowsEnvironment()
    assert machine.call(env, "GetCurrentProcess") == PE.MASK64
    out = machine.call(env, "GetStdHandle", (1 << 32) - 11)
    machine.write(0x4000, b"x64")
    assert machine.call(env, "WriteFile", out, 0x4000, 3, 0x4100, 0) == 1 and bytes(env.stdout) == b"x64"
    machine.write(0x2000, b"\xEE" * 16)
    machine.call(env, "NtQueryInformationProcess", PE.MASK64, PE.PROCESS_DEBUG_PORT, 0x2000, 8, 0x2100)
    assert machine.read(0x2000, 9) == b"\0" * 8 + b"\xEE"                  # eight bytes on x64
    assert machine.call(env, "HeapSize", 0, 0, 0x5555) == PE.MASK64
    assert "eax" not in machine.regs


def test_mapped_pe_keeps_its_positional_shape():
    pe = PE.map_pe(build_pe32())
    assert pe.delay_imports == () and dataclasses.fields(pe)[-1].name == "delay_imports"


def test_the_pe_native_brief_names_the_b241_on_ramp():
    """The swarm brief cites the new entry points by name; each one exists (a rename would strand it)."""
    from solvers.binary import unpack_worker
    from solvers.toolkits import native_loaders

    text = (ROOT / "templates" / "static-re" / "pe-native.md.tmpl").read_text(encoding="utf-8")
    for name in ("delay_imports", "dump_pe", "rebuilt_imports", "stop_on_written_exec", "track_image_writes",
                 "unpack_worker.py", "native_loaders.report", "RtlUnwind", "stdin", "command_line"):
        assert name in text, name
    assert hasattr(PE, "dump_pe") and hasattr(PE, "rebuilt_imports") and "dump_pe" in PE.__all__
    assert "delay_imports" in {f.name for f in dataclasses.fields(PE.MappedPE)}
    assert {"stdin", "command_line", "stdout"} <= {f.name for f in dataclasses.fields(PE.WindowsEnvironment)}
    assert callable(unpack_worker.unpack) and callable(native_loaders.report)
    import inspect
    assert "stop_on_written_exec" in inspect.signature(PE.SafeUnicorn.run).parameters
    assert "track_image_writes" in inspect.signature(PE.SafeUnicorn.__init__).parameters
