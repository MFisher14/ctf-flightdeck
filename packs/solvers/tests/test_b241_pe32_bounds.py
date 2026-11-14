#!/usr/bin/env python3
"""B-241 (verification round 1): the named denials and boundaries of the PE32 sandbox, and the state a
snapshot, restore and fork must carry.

The fixture PE is ``test_b241_pe32.build_pe32``; small pieces of code are hand-encoded into its writable and
executable ``.pack`` section (each encoding is checked against capstone before it runs).  The tests drive
the guarded real Unicorn backend and are marked ``needs_tool``: where the engine is unavailable they skip
with a named reason, so they report NOT RUN, never green.
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

from solvers.toolkits import pe_emu as PE  # noqa: E402
from test_b241_pe32 import A, BASE, D, PACKED, TEXT, build_pe32, cell, poke, sandbox  # noqa: E402

engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")

IAT0 = BASE + 0x2100
HANDLER = PACKED + 0x80


def code(box, raw, mnemonics, at=PACKED):
    """Write hand-encoded ``raw`` at ``at`` after checking that capstone reads ``mnemonics`` from it."""
    capstone = pytest.importorskip("capstone")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    got = [ins.mnemonic for ins in decoder.disasm(raw, at)]
    assert got == mnemonics.split(), got
    box.write_memory(at, raw)
    return at


def api(box, env, name, *args):
    """Carry out modelled API ``name`` on the sandbox as a stdcall from the current stack."""
    esp = box.read_register("esp")
    box.write(esp, struct.pack("<I", 0xDEAD) + b"".join(struct.pack("<I", value & 0xFFFFFFFF) for value in args))
    env.dispatch(PE.ImportSymbol("kernel32.dll", name, None, 0), box)
    return box.read_register("eax")


def seh_function(box, dr0):
    """A function that installs a handler which sets CONTEXT.Dr0 to ``dr0``, skips the int3 and continues."""
    code(box, b"\x8b\x4c\x24\x0c"                       # mov ecx, [esp+0xC]   (ContextRecord)
         + b"\xc7\x41\x04" + struct.pack("<I", dr0)     # mov dword [ecx+4], dr0   (CONTEXT.Dr0)
         + b"\xff\x81\xb8\x00\x00\x00"                  # inc dword [ecx+0xB8]     (CONTEXT.Eip past the int3)
         + b"\x31\xc0\xc3",                             # xor eax, eax ; ret       (ExceptionContinueExecution)
         "mov mov inc xor ret", at=HANDLER)
    return code(box, b"\x68" + struct.pack("<I", HANDLER)                   # push handler
                + b"\x64\xff\x35\x00\x00\x00\x00"                           # push dword fs:[0]
                + b"\x64\x89\x25\x00\x00\x00\x00"                           # mov fs:[0], esp
                + b"\xcc"                                                   # int3
                + b"\x64\x8f\x05\x00\x00\x00\x00"                           # pop dword fs:[0]
                + b"\x83\xc4\x04"                                           # add esp, 4
                + b"\xb8\x34\x12\x00\x00\xc3",                              # mov eax, 0x1234 ; ret
                "push push mov int3 pop add mov ret")


# ------------------------------------------------------------------ exception dispatch denials
@engine
def test_a_handler_that_sets_a_debug_register_through_context_is_denied():
    box = sandbox(build_pe32())
    assert box.call(seh_function(box, 0)).reason == "return"              # control: Dr0 left at zero
    assert box.read_register("eax") == 0x1234
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="set debug registers through CONTEXT"):
        box.call(seh_function(box, 0x401000))


@engine
def test_an_unknown_seh_disposition_is_denied_not_searched_on():
    box = sandbox(build_pe32())
    poke(box, "DISP", 2)                                                   # ExceptionNestedException
    with pytest.raises(PE.EmulationDenied, match="returned disposition 2, which is not modelled"):
        box.call(A["m_int3"])


@engine
def test_a_vectored_handler_answer_that_is_no_disposition_is_denied():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(("kernel32.dll", ("AddVectoredExceptionHandler",))), environment=env)
    poke(box, "VEHDISP", 5)
    with pytest.raises(PE.EmulationDenied, match="vectored handler returned 0x5, which is not a disposition"):
        box.call(A["m_veh"])


@engine
@pytest.mark.parametrize("frame,reason", [
    (PE.SafeUnicorn.STACK_BASE + 0x1002, "is not an aligned record on the stack"),     # misaligned
    (PACKED, "is not an aligned record on the stack"),                                 # not on the stack
    (PE.SafeUnicorn.STACK_BASE + 0x1000, "holds undefined bytes"),                     # never written
])
def test_a_bad_seh_registration_record_is_denied(frame, reason):
    box = sandbox(build_pe32())
    box.write_memory(box.TEB_BASE, struct.pack("<I", frame))              # FS:[0], the chain head
    with pytest.raises(PE.EmulationDenied, match=reason):
        box.call(A["m_bare"])


@engine
def test_the_two_byte_int3_form_is_denied_by_name():
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="two-byte int 3 form"):
        box.call(code(box, b"\xcd\x03\xc3", "int ret"))
    assert box.exception_trace == []


def unwind_call(box, target):
    return code(box, b"\x6a\x00\x6a\x00\x6a\x00\x68" + struct.pack("<I", target)   # RtlUnwind(target, 0, 0, 0)
                + b"\xff\x15" + struct.pack("<I", IAT0) + b"\xc3", "push push push push call ret")


@engine
def test_rtl_unwind_denies_an_exit_unwind_and_a_target_off_the_chain():
    raw = build_pe32(("ntdll.dll", ("RtlUnwind",)))
    box = sandbox(raw, environment=PE.WindowsEnvironment())
    with pytest.raises(PE.EmulationDenied, match="NULL target frame"):
        box.call(unwind_call(box, 0))
    box = sandbox(raw, environment=PE.WindowsEnvironment())
    with pytest.raises(PE.EmulationDenied, match="target frame is not on the handler chain"):
        box.call(unwind_call(box, box.STACK_BASE + 0x1000))


# ------------------------------------------------------------------ the null area and page protections
@engine
def test_the_whole_first_64_kib_faults_and_the_page_above_it_is_only_unmapped():
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="unhandled exception 0xc0000005"):
        box.call(code(box, b"\xa1\xfc\xff\x00\x00\xc3", "mov ret"))        # mov eax, [0xFFFC]
    assert box.exception_trace == [(PE.EXCEPTION_ACCESS_VIOLATION, PACKED)]
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="unmapped/protection memory access denied at 0x10000"):
        box.call(code(box, b"\xa1\x00\x00\x01\x00\xc3", "mov ret"))        # mov eax, [0x10000]
    assert box.exception_trace == []                                       # no Windows exception for it


@engine
def test_protect_changes_exactly_the_pages_its_range_touches():
    box = sandbox(build_pe32())
    idata = BASE + 0x2000
    assert box.protect(TEXT, 0x1000, 0x40) == 0x20                         # one whole page: .text only
    assert box.protect(idata, 0x1000, 0x04) == 0x04                        # .idata kept PAGE_READWRITE
    assert box.protect(TEXT + 0xFFF, 2, 0x02) == 0x40                      # two bytes across the boundary
    assert box.protect(idata, 0x1000, 0x04) == 0x02                        # ... reach .idata as well
    with pytest.raises(PE.EmulationDenied):
        box.write_memory(TEXT, b"\x90")                                    # .text is read-only now


@engine
def test_bytes_a_modelled_api_writes_count_for_the_written_exec_stop():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(), environment=env, track_image_writes=True)
    box.write_memory(box.SCRATCH_BASE, bytes.fromhex("b8ed5e0000c3"))      # mov eax, 0x5EED ; ret
    api(box, env, "RtlMoveMemory", PACKED, box.SCRATCH_BASE, 6)
    assert bytes(box.image_written[0x4000:0x4006]) == b"\x01" * 6
    result = box.run(PACKED, stop_on_written_exec=True)
    assert (result.reason, result.address) == ("written-exec", PACKED)


# ------------------------------------------------------------------ CPU state a Windows thread holds
@engine
@pytest.mark.parametrize("raw,mnemonics,selector", [
    (b"\x8c\xc8\xc3", "mov ret", "CS"),          # mov eax, cs
    (b"\x8c\xd0\xc3", "mov ret", "SS"),          # mov eax, ss
    (b"\x0e\x58\xc3", "push pop ret", "CS"),     # push cs ; pop eax
    (b"\x16\x58\xc3", "push pop ret", "SS"),     # push ss ; pop eax
    (b"\x8e\xd0\xc3", "mov ret", "SS"),          # mov ss, eax
    (b"\x0f\xb2\x05" + struct.pack("<I", PACKED + 0x40) + b"\xc3", "lss ret", "SS"),
    (b"\xea" + struct.pack("<IH", PACKED + 7, 0x33) + b"\xc3", "ljmp ret", "CS"),     # heaven's gate
    (b"\x9a" + struct.pack("<IH", PACKED + 7, 0x23) + b"\xc3", "lcall ret", "CS"),
    (b"\xcb", "retf", "CS"),
    (b"\xff\x2d" + struct.pack("<I", PACKED + 0x40) + b"\xc3", "jmp ret", "CS"),       # jmp far [m16:32]
    (b"\xff\x1d" + struct.pack("<I", PACKED + 0x40) + b"\xc3", "call ret", "CS"),      # call far [m16:32]
])
def test_reading_or_loading_cs_or_ss_is_denied(raw, mnemonics, selector):
    box = sandbox(build_pe32())
    box.write_memory(PACKED + 0x40, struct.pack("<IH", PACKED + 0x50, 0x23))
    with pytest.raises(PE.EmulationDenied, match=f"touches the {selector} selector"):
        box.call(code(box, raw, mnemonics))


@engine
def test_a_near_indirect_jump_is_not_mistaken_for_a_far_one():
    box = sandbox(build_pe32())
    box.write_memory(PACKED + 0x40, struct.pack("<I", PACKED + 0x50))
    code(box, b"\xb8\x77\x00\x00\x00\xc3", "mov ret", at=PACKED + 0x50)               # mov eax, 0x77 ; ret
    assert box.call(code(box, b"\xff\x25" + struct.pack("<I", PACKED + 0x40), "jmp")).reason == "return"
    assert box.read_register("eax") == 0x77


@engine
@pytest.mark.parametrize("raw,mnemonics", [
    (b"\x0f\x20\xc0\xc3", "mov ret"),            # mov eax, cr0
    (b"\x0f\x21\xf8\xc3", "mov ret"),            # mov eax, dr7
    (b"\x0f\x23\xf8\xc3", "mov ret"),            # mov dr7, eax
    (b"\x0f\x32\xc3", "rdmsr ret"),
])
def test_control_and_debug_register_access_is_a_privileged_instruction(raw, mnemonics):
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="unhandled exception 0xc0000096"):
        box.call(code(box, raw, mnemonics))
    assert box.exception_trace == [(PE.EXCEPTION_PRIV_INSTRUCTION, PACKED)]


@engine
def test_the_thread_starts_with_windows_flags_and_data_selectors():
    # A fresh sandbox per read: each piece of code goes to the same address, and the engine keeps
    # its translation of the bytes it ran there first.
    for raw, mnemonics, mask, want in ((b"\x9c\x58\xc3", "pushfd pop ret", 0xFFFFFFFF, 0x202),  # IF set
                                       (b"\x8c\xd8\xc3", "mov ret", 0xFFFF, 0x23),              # DS: flat ring 3
                                       (b"\x8c\xe0\xc3", "mov ret", 0xFFFF, 0x3B)):             # FS: the TEB
        box = sandbox(build_pe32())
        assert box.call(code(box, raw, mnemonics)).reason == "return"
        assert box.read_register("eax") & mask == want


# ------------------------------------------------------------------ snapshot, restore and fork
@engine
def test_restoring_a_snapshot_rewinds_the_stdin_cursor_and_forks_read_independently():
    env = PE.WindowsEnvironment(stdin=b"hello")
    box = sandbox(build_pe32(), environment=env)
    inp = api(box, env, "GetStdHandle", -10)
    start = box.snapshot()
    reads = []
    for _ in range(3):
        box.restore(start)
        api(box, env, "ReadFile", inp, box.SCRATCH_BASE, 4, 0, 0)
        reads.append(box.read_memory(box.SCRATCH_BASE, 4))
    assert reads == [b"hell"] * 3
    box.restore(start)
    api(box, env, "ReadFile", inp, box.SCRATCH_BASE, 2, 0, 0)               # the parent has read "he"
    child = box.fork(start)
    api(child, env, "ReadFile", inp, child.SCRATCH_BASE, 2, 0, 0)
    assert child.read_memory(child.SCRATCH_BASE, 2) == b"he"               # the child starts at the snapshot
    api(box, env, "ReadFile", inp, box.SCRATCH_BASE, 2, 0, 0)
    assert box.read_memory(box.SCRATCH_BASE, 2) == b"ll"                   # ... and did not move the parent


@engine
def test_the_command_line_buffer_follows_a_restore():
    env = PE.WindowsEnvironment(command_line="crackme.exe key")
    box = sandbox(build_pe32(), environment=env)
    start = box.snapshot()
    first = api(box, env, "GetCommandLineA")
    assert box.read_memory(first, 16) == b"crackme.exe key\0"
    box.restore(start)                                                     # the heap buffer is gone again
    again = api(box, env, "GetCommandLineA")
    assert again == first and box.read_memory(again, 16) == b"crackme.exe key\0"
    other = sandbox(build_pe32(), environment=env)                          # one model, a second process
    assert other.read_memory(api(other, env, "GetCommandLineA"), 16) == b"crackme.exe key\0"


@engine
def test_page_protections_and_written_bytes_travel_with_a_snapshot():
    box = sandbox(build_pe32(), track_image_writes=True)
    before = box.snapshot()
    assert box.protect(TEXT, 0x1000, 0x40) == 0x20
    box.write(PACKED, b"\x90")
    after = box.snapshot()
    child = box.fork(after)                                                # a fresh harness gets the new layout
    child.write_memory(TEXT, b"\x90")                                      # .text is writable in the fork
    assert child.image_written[0x4000] == 1 and child.protect(TEXT, 0x1000, 0x20) == 0x40
    box.restore(before)
    assert box.image_written[0x4000] == 0
    with pytest.raises(PE.EmulationDenied):
        box.write_memory(TEXT, b"\x90")                                    # read-only again
    heap = box.alloc(0x100)
    box.restore(before)
    assert box.alloc(0x100) == heap                                        # the heap cursor rewinds too


@engine
def test_a_snapshot_that_does_not_fit_the_harness_is_refused():
    box = sandbox(build_pe32(), track_image_writes=True)
    snap = box.snapshot()
    for bad, reason in ((dataclasses.replace(snap, page_perms=snap.page_perms[:-1]), "page protections"),
                        (dataclasses.replace(snap, heap_ptr=None), "heap cursor"),
                        (dataclasses.replace(snap, heap_ptr=box.HEAP_BASE - 1), "heap cursor"),
                        (dataclasses.replace(snap, image_written=None), "write tracking"),
                        (dataclasses.replace(snap, page_perms=(0x10,) * len(snap.page_perms)),
                         "not a permission set")):
        with pytest.raises(PE.EmulationDenied, match=reason):
            box.restore(bad)
    plain = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match="write tracking"):
        plain.restore(snap)


# ------------------------------------------------------------------ delay imports
def test_two_delay_descriptors_sharing_one_slot_are_refused():
    raw = bytearray(build_pe32(delay=("kernel32.dll", "SetLastError")))
    descriptor = 0xA00 + 0x200
    raw[descriptor + 32:descriptor + 64] = raw[descriptor:descriptor + 32]   # a second descriptor, same IAT
    assert len(PE.map_pe(build_pe32(delay=("kernel32.dll", "SetLastError"))).delay_imports) == 1
    with pytest.raises(PE.PEError, match="shared"):
        PE.map_pe(bytes(raw))


def test_cell_names_cover_the_listing():
    """The data cells the shared helpers poke exist (a renamed cell would make a denial test vacuous)."""
    assert {"DISP", "VEHDISP"} <= set(D) and callable(cell)
