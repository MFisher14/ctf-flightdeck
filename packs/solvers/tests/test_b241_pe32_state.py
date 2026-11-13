#!/usr/bin/env python3
"""B-241 (verification round 2): what a PE32 snapshot must carry so a restore or fork replays a run, and
the ring-3 CPU state the sandbox keeps although the engine runs the thread at ring 0.

Fixture: ``test_b241_pe32.build_pe32`` with small hand-encoded pieces in its writable and executable
``.pack`` section (each encoding is checked against capstone before it runs).  The engine tests drive the
guarded real Unicorn backend and are marked ``needs_tool``: where it is unavailable they skip with a named
reason (NOT RUN), never green.
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
from test_b241_pe32 import BASE, PACKED, TEXT, build_pe32, sandbox  # noqa: E402
from test_b241_pe32_bounds import api, code  # noqa: E402

engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")

IAT0 = BASE + 0x2100
TEXT_HEAD = bytes.fromhex("8b542404")          # the first instruction of the listing (add2: mov edx, [esp+4])
RET1 = bytes.fromhex("b801000000c3")           # mov eax, 1 ; ret
RET2 = bytes.fromhex("b802000000c3")           # mov eax, 2 ; ret
TARGET = PACKED + 0x100


def returns(box, at):
    result = box.call(at)
    assert result.reason == "return"
    return box.read_register("eax")


# ------------------------------------------------------------------ image pages and translated code
@engine
def test_a_restore_puts_back_an_image_page_made_writable_after_the_snapshot():
    box = sandbox(build_pe32())
    before = box.snapshot()
    assert box.protect(TEXT, 0x1000, 0x40) == 0x20                       # VirtualProtect .text to RWX
    box.write(TEXT, b"\xcc" * 4)
    box.restore(before)
    assert box.read_memory(TEXT, 4) == TEXT_HEAD                         # the unpacker's bytes are gone
    assert box.fork(before).read_memory(TEXT, 4) == TEXT_HEAD
    with pytest.raises(PE.EmulationDenied):
        box.write_memory(TEXT, b"\x90")                                  # and .text is read-only again
    assert ({row.name for row in box.snapshot().memory}
            == {row.name for row in before.memory})                     # nothing is remembered as written


@engine
def test_a_page_written_then_protected_again_travels_with_the_snapshot():
    box = sandbox(build_pe32())
    box.protect(TEXT, 0x1000, 0x40)
    box.write(TEXT, b"\xcc" * 4)
    assert box.protect(TEXT, 0x1000, 0x20) == 0x40                       # back to RX, as an unpacker leaves it
    unpacked = box.snapshot()
    child = sandbox(build_pe32())
    child.restore(unpacked)
    assert child.read_memory(TEXT, 4) == b"\xcc" * 4
    with pytest.raises(PE.EmulationDenied):
        child.write_memory(TEXT, b"\x90")                                # with the protection it had


@engine
def test_a_restore_drops_code_the_engine_translated_after_the_snapshot():
    box = sandbox(build_pe32())
    code(box, RET1, "mov ret", at=TARGET)
    code(box, b"\xc6\x05" + struct.pack("<I", TARGET + 1) + b"\x02\xc3", "mov ret")   # mov byte [TARGET+1], 2
    start = box.snapshot()
    assert returns(box, TARGET) == 1
    returns(box, PACKED)                                                 # the guest rewrites TARGET
    assert returns(box, TARGET) == 2
    box.restore(start)
    assert box.read_memory(TARGET, 6) == RET1
    assert returns(box, TARGET) == 1                                     # not the stale translation


@engine
def test_an_analyst_write_over_code_that_already_ran_takes_effect():
    box = sandbox(build_pe32())
    code(box, RET1, "mov ret", at=TARGET)
    assert returns(box, TARGET) == 1
    code(box, RET2, "mov ret", at=TARGET)
    assert returns(box, TARGET) == 2


@engine
def test_a_modelled_api_that_writes_over_code_during_a_run_takes_effect():
    """ReadFile into a code buffer the run has already executed, then a call into it: the API write is a
    host write the engine does not see, so its translation of the buffer has to be dropped."""
    env = PE.WindowsEnvironment(stdin=RET2)
    box = sandbox(build_pe32(("kernel32.dll", ("ReadFile",))), environment=env)
    code(box, RET1, "mov ret", at=TARGET)

    def rel(at):
        return struct.pack("<i", TARGET - (at + 5))

    driver = b"\xe8" + rel(PACKED)                                       # call TARGET
    driver += b"\x6a\x00\x6a\x00\x6a\x06\x68" + struct.pack("<I", TARGET)  # push 0; push 0; push 6; push TARGET
    driver += b"\x68" + struct.pack("<I", PE._PSEUDO_STDIN)             # push hStdin
    driver += b"\xff\x15" + struct.pack("<I", IAT0)                      # call [ReadFile]
    driver += b"\xe8" + rel(PACKED + len(driver)) + b"\xc3"              # call TARGET ; ret
    code(box, driver, "call push push push push push call call ret")
    assert returns(box, PACKED) == 2


# ------------------------------------------------------------------ the snapshot's own consistency
@engine
def test_a_snapshot_whose_image_rows_do_not_fit_is_refused():
    box = sandbox(build_pe32())
    snap = box.snapshot()
    rows = list(snap.memory)
    image = [index for index, row in enumerate(rows) if row.name.startswith("image+")]
    assert image, "the writable image sections are carried as image rows"
    first = rows[image[0]]
    shifted = dataclasses.replace(first, start=first.start + 0x1000)
    for memory, reason in (
            (rows + [first], "overlap"),
            ([row for index, row in enumerate(rows) if index != image[-1]], "omits the bytes of a writable"),
            ([shifted if row is first else row for row in rows], "does not fit"),
            ([dataclasses.replace(first, data=first.data[:-1]) if row is first else row for row in rows],
             "does not fit"),
            ([dataclasses.replace(first, name="image+zz") if row is first else row for row in rows],
             "named by its offset")):
        with pytest.raises(PE.EmulationDenied, match=reason):
            box.restore(dataclasses.replace(snap, memory=tuple(memory)))
    box.restore(snap)                                                    # the untouched snapshot still fits


@engine
def test_a_snapshot_of_an_image_mapped_differently_is_refused():
    raw = build_pe32(delay=("kernel32.dll", "SetLastError"))
    bound = sandbox(raw)
    unbound = sandbox(raw, bind_delay_imports=False)
    with pytest.raises(PE.EmulationDenied, match="mapped differently"):
        unbound.restore(bound.snapshot())
    unbound.restore(unbound.snapshot())


# ------------------------------------------------------------------ per-process Windows state
def veh_continue_handler(box):
    """A vectored handler that skips the int3 and continues: EXCEPTION_POINTERS -> ContextRecord.Eip += 1."""
    return code(box, b"\x8b\x44\x24\x04"            # mov eax, [esp+4]
                + b"\x8b\x48\x04"                   # mov ecx, [eax+4]   (ContextRecord)
                + b"\xff\x81\xb8\x00\x00\x00"       # inc dword [ecx+0xB8]
                + b"\xb8\xff\xff\xff\xff"           # mov eax, EXCEPTION_CONTINUE_EXECUTION
                + b"\xc2\x04\x00",                  # ret 4
                "mov mov inc mov ret", at=PACKED + 0x80)


@engine
def test_the_vectored_handler_chain_travels_with_a_snapshot():
    box = sandbox(build_pe32())
    handler = veh_continue_handler(box)
    fault = code(box, b"\xcc\xb8\x77\x00\x00\x00\xc3", "int3 mov ret")   # int3 ; mov eax, 0x77 ; ret
    before = box.snapshot()
    box.add_veh(True, handler)
    after = box.snapshot()
    assert returns(box.fork(after), fault) == 0x77                       # the fork keeps the handler
    box.restore(before)
    with pytest.raises(PE.EmulationDenied):
        box.call(fault)                                                  # restored: no handler continues it
    box.restore(after)
    assert returns(box, fault) == 0x77
    for bad in (((0, handler),), ((5, handler),), ((1, handler), (1, handler)), ((1, 0),)):
        with pytest.raises(PE.EmulationDenied, match="vectored-handler chain"):
            box.restore(dataclasses.replace(after, veh=bad, veh_next_cookie=2))


@engine
def test_last_error_counters_and_allocations_rewind_with_a_restore():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(), environment=env)
    first_tick = api(box, env, "GetTickCount")
    start = box.snapshot()
    api(box, env, "SetLastError", 0x57)
    assert api(box, env, "GetLastError") == 0x57 and env.last_error == 0x57
    second_tick = api(box, env, "GetTickCount")
    assert second_tick == first_tick + 16
    block = api(box, env, "HeapAlloc", 0x1000, 0, 0x30)
    assert api(box, env, "HeapSize", 0x1000, 0, block) == 0x30
    box.restore(start)
    assert api(box, env, "GetLastError") == 0                            # not the value set after the snapshot
    assert api(box, env, "GetTickCount") == second_tick                   # the counter replays
    assert api(box, env, "HeapSize", 0x1000, 0, block) == 0xFFFFFFFF      # the block was never allocated
    child = box.fork(start)
    assert api(child, env, "GetTickCount") == second_tick


@engine
def test_each_sandbox_is_its_own_process_for_last_error_and_the_clock():
    env = PE.WindowsEnvironment(tick=0x5000)
    one = sandbox(build_pe32(), environment=env)
    api(one, env, "SetLastError", 0x57)
    assert api(one, env, "GetTickCount") == 0x5000
    other = sandbox(build_pe32(), environment=env)
    assert api(other, env, "GetLastError") == 0
    assert api(other, env, "GetTickCount") == 0x5000                     # starts where the model says


@engine
def test_the_performance_and_file_time_counters_rewind_with_a_restore():
    env = PE.WindowsEnvironment()
    box = sandbox(build_pe32(), environment=env)
    out = box.SCRATCH_BASE
    start = box.snapshot()
    api(box, env, "QueryPerformanceCounter", out)
    perf = box.read_memory(out, 8)
    api(box, env, "GetSystemTimeAsFileTime", out)
    filetime = box.read_memory(out, 8)
    box.restore(start)
    api(box, env, "QueryPerformanceCounter", out)
    assert box.read_memory(out, 8) == perf
    api(box, env, "GetSystemTimeAsFileTime", out)
    assert box.read_memory(out, 8) == filetime


# ------------------------------------------------------------------ ring-3 state at ring 0
@engine
@pytest.mark.parametrize("raw,mnemonics,changed", [
    (b"\x9c\x81\x0c\x24\x00\x30\x00\x00\x9d\x9c\x58\xc3", "pushfd or popfd pushfd pop ret", "IOPL"),
    (b"\x9c\x81\x24\x24\xff\xfd\xff\xff\x9d\x9c\x58\xc3", "pushfd and popfd pushfd pop ret", "IF"),
    (b"\x66\x9c\x66\x81\x24\x24\xff\xfd\x66\x9d\x9c\x58\xc3", "pushf and popf pushfd pop ret", "IF"),
    (b"\x6a\x00\x9d\x9c\x58\xc3", "push popfd pushfd pop ret", "IF"),
])
def test_a_popf_that_would_change_if_or_iopl_is_denied(raw, mnemonics, changed):
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match=f"would change {changed}: a ring-3 thread keeps it"):
        box.call(code(box, raw, mnemonics))


@engine
def test_a_popf_that_keeps_if_and_iopl_runs():
    box = sandbox(build_pe32())
    raw = b"\x9c\x81\x0c\x24\x01\x08\x00\x00\x9d\x9c\x58\xc3"           # set CF and OF through popfd
    assert returns(box, code(box, raw, "pushfd or popfd pushfd pop ret")) & 0x3A01 == 0x0A01


@engine
def test_nt_continue_keeps_if_set_and_iopl_zero_whatever_the_context_says():
    box = sandbox(build_pe32())
    handler = PACKED + 0x80
    code(box, b"\x8b\x4c\x24\x0c"                                        # mov ecx, [esp+0xC] (ContextRecord)
         + b"\xc7\x81\xc0\x00\x00\x00\x03\x30\x02\x00"                   # mov dword [ecx+0xC0], 0x23003
         + b"\xff\x81\xb8\x00\x00\x00"                                   # inc dword [ecx+0xB8]
         + b"\x31\xc0\xc3", "mov mov inc xor ret", at=handler)
    main = code(box, b"\x68" + struct.pack("<I", handler)               # push handler
                + b"\x64\xff\x35\x00\x00\x00\x00"                       # push dword fs:[0]
                + b"\x64\x89\x25\x00\x00\x00\x00"                       # mov fs:[0], esp
                + b"\xcc"                                               # int3
                + b"\x9c\x58"                                           # pushfd ; pop eax
                + b"\x64\x8f\x05\x00\x00\x00\x00"                       # pop dword fs:[0]
                + b"\x83\xc4\x04\xc3",                                  # add esp, 4 ; ret
                "push push mov int3 pushfd pop pop add ret")
    flags = returns(box, main)
    assert flags & 0x200 and not flags & 0x3000 and not flags & 0x20000
    assert flags & 0x1                                                   # CF from the CONTEXT is kept


@engine
@pytest.mark.parametrize("raw,mnemonics,register", [
    (b"\x66\x8c\xd8\x8e\xc0\xc3", "mov mov ret", "ES"),                 # mov ax, ds ; mov es, ax
    (b"\x1e\x1f\xc3", "push pop ret", "DS"),                            # push ds ; pop ds
    (b"\x0f\xa0\x0f\xa1\xc3", "push pop ret", "FS"),                    # push fs ; pop fs
    (b"\xc4\x05" + struct.pack("<I", PACKED + 0x40) + b"\xc3", "les ret", "ES"),
])
def test_a_segment_register_load_is_denied_by_name(raw, mnemonics, register):
    box = sandbox(build_pe32())
    with pytest.raises(PE.EmulationDenied, match=f"loads the {register} segment register"):
        box.call(code(box, raw, mnemonics))


@engine
def test_reading_the_data_selectors_still_runs():
    box = sandbox(build_pe32())
    raw = b"\x31\xc0\x66\x8c\xc0\xc3"                                    # xor eax, eax ; mov ax, es ; ret
    assert returns(box, code(box, raw, "xor mov ret")) == 0x23
    raw = b"\x1e\x58\xc3"                                                # push ds ; pop eax ; ret
    assert returns(box, code(box, raw, "push pop ret")) & 0xFFFF == 0x23
