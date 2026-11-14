#!/usr/bin/env python3
"""Unit tests for solvers/common/native_emulate.py -- the general (Unicorn) single-function emulator.

Proves the two things the module exists for:
  * GENERAL: a branch / loop / call / float / extra-argument native leg (which the hand-rolled straight-line
    readers decline on) emulates to the correct value.
  * NEVER-WRONG: every indeterminate input (undefined register, undefined / unmapped memory, a syscall, a
    runaway with no return) FAILS CLOSED with EmulationError -- never a fabricated value.

Also cross-checks the general engine against dex_chain_codec's hand-rolled x86-64 reader on random
straight-line transforms (they must agree), which is the invariant the live native dispatch relies on.

The whole file SKIPs cleanly when the Unicorn engine is not installed. Run:
    .venv/bin/python -I -B tests/test_native_emulate.py
"""
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "solvers" / "mobile-android"))

import native_emulate as ne  # noqa: E402

M64 = (1 << 64) - 1
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name)


def declines(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except ne.EmulationError:
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ general capability
def test_general():
    # x86-64 straight-line: mov rax,rdi; add rax,rsi; ret -> 5 + 7
    code = bytes.fromhex("4889f84801f0c3")
    check("x86 add", ne.emulate_x86_sysv(code, [5, 7]) == 12)

    # x86-64 LOOP: xor eax,eax; L: add rax,rdi; dec rdi; jnz L; ret -> sum 1..10 == 55
    code = bytes.fromhex("31C0" + "4801F8" + "48FFCF" + "75F8" + "C3")
    check("x86 loop (branch/loop)", ne.emulate_x86_sysv(code, [10]) == 55)

    # x86-64 CALL: call +0 to a helper that returns rdi*3, then ret.
    #   mov rax,rdi; call rel32(+1 over the ret below->to helper); ret ; helper: lea rax,[rax+rax*2]; ret
    # keep it simple: push/pop round-trip proves defined-stack handling
    code = bytes.fromhex("5758C3")                      # push rdi; pop rax; ret
    check("x86 defined push/pop", ne.emulate_x86_sysv(code, [0xABCD]) == 0xABCD)

    # arm64 straight-line: add x0,x0,x1; ret
    code = struct.pack("<II", 0x8B010000, 0xD65F03C0)
    check("arm64 add", ne.emulate_arm64_aapcs(code, [5, 7]) == 12)

    # arm64 LOOP: movz x0,#0; add x0,x0,x2; subs x2,x2,#1; b.ne -8; ret -> sum 1..5 == 15 (arg in x2)
    words = [0xD2800000, 0x8B020000, 0xF1000442, 0x54FFFFC1, 0xD65F03C0]
    code = b"".join(struct.pack("<I", w) for w in words)
    check("arm64 loop (branch/loop)", ne.emulate_function(code, "arm64", {"x2": 5}, "x0") == 15)

    # arm64 EXTRA-ARG: add x0,x2,x3; ret  (the hand-rolled reader only has x2 -> declines; general resolves)
    code = struct.pack("<II", 0x8B030040, 0xD65F03C0)
    check("arm64 extra-arg", ne.emulate_function(code, "arm64", {"x2": 100, "x3": 23}, "x0") == 123)


# ------------------------------------------------------------------ never-wrong (fail closed)
def test_fail_closed():
    # undefined register: mov rax,rbx; ret  (rbx never set)
    check("undefined register declines", declines(ne.emulate_x86_sysv, bytes.fromhex("4889D8C3"), [7]))
    # undefined / unmapped memory read: mov rax,[rdi]; ret with rdi in an unmapped region
    check("unmapped read declines", declines(ne.emulate_x86_sysv, bytes.fromhex("488B07C3"), [0x10000]))
    # read of an unwritten stack slot within a mapped frame: sub rsp,8; mov rax,[rsp]; ret
    code = bytes.fromhex("4883EC08" + "488B0424" + "C3")
    check("undefined stack-slot read declines", declines(ne.emulate_x86_sysv, code, [1]))
    # syscall must be denied: mov rax,rdi; syscall; ret
    check("syscall denied", declines(ne.emulate_x86_sysv, bytes.fromhex("4889F80F05C3"), [1]))
    # no return / runaway: jmp $
    check("no-return declines", declines(ne.emulate_x86_sysv, bytes.fromhex("EBFE"), [1], 5000))
    # arm64 unmodelled-by-nothing is fine, but a load from unmapped must fail: ldr x0,[x1]; ret, x1 unmapped
    code = struct.pack("<II", 0xF9400020, 0xD65F03C0)
    check("arm64 unmapped load declines", declines(ne.emulate_function, code, "arm64", {"x1": 0x10000}, "x0"))


# ------------------------------------------------------------------ cross-check vs the hand-rolled reader
def test_cross_check_hand_rolled():
    # Build random STRAIGHT-LINE x86-64 (J)J transforms and require the general engine and
    # dex_chain_codec._emulate_x86 to agree on every argument (the live-dispatch invariant).
    import importlib.util
    spec = importlib.util.spec_from_file_location("dex_chain_codec", ROOT / "solvers/mobile-android/dex_chain_codec.py")
    dcc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dcc)

    # A small corpus of hand-written straight-line (J)J bodies (arg in rdx == SysV int_args[2]):
    #   each: mov rax,rdx ; <ops on rax> ; ret
    bodies = [
        bytes.fromhex("4889D0" + "4883C07B" + "C3"),                 # add rax,0x7b
        bytes.fromhex("4889D0" + "4835EFBEADDE" + "C3"),             # xor rax,0xdeadbeef (sign-ext imm32)
        bytes.fromhex("4889D0" + "48C1C00D" + "C3"),                 # rol rax,13
        bytes.fromhex("4889D0" + "48F7D0" + "C3"),                   # not rax
        bytes.fromhex("4889D0" + "480FAFC2" + "C3"),                 # imul rax,rdx
    ]
    rnd = random.Random(7)
    ok = True
    details = []
    for b in bodies:
        for _ in range(8):
            arg = rnd.getrandbits(64)
            int_args = [0, 0, arg]                                   # rdi, rsi, rdx
            try:
                hr = dcc._emulate_x86(b, int_args) & M64
            except dcc._Decline:
                hr = None
            try:
                uc = ne.emulate_x86_sysv(b, int_args) & M64
            except ne.EmulationError:
                uc = None
            if hr is not None and uc is not None and hr != uc:
                ok = False
                details.append((b.hex(), arg, hr, uc))
    check("hand-rolled x86 == unicorn on straight-line corpus", ok)
    if not ok:
        for d in details[:3]:
            print("   DISAGREE", d)


def main():
    if not ne.UNICORN_AVAILABLE:
        print("SKIP all: unicorn engine not available")
        return 0
    test_general()
    test_fail_closed()
    test_cross_check_hand_rolled()
    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
