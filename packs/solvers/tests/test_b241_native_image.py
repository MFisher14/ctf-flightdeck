#!/usr/bin/env python3
"""B-241: Android packed (APS2) relocations, float JNI and the JNI reference lifecycle in native_image.

Fixtures are synthetic: hand-built ELF64 shared objects whose code is the listing
``tests/fixtures/native_image/B241_JNI_X86_64.s`` / ``B241_FP_ARM64.s`` (assembled into
``tests/b241_blobs.py``), and the committed KB-2 fixture ``kb2_jni_*.so`` re-packed in the test.  Nothing
is run on the host: the code runs inside the bounded whole-image emulator.  Tests that need the engine
are marked ``needs_tool`` and skip with a named reason where it is unavailable (NOT RUN, never green).
"""
from __future__ import annotations

import struct
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT, ROOT / "tests", ROOT / "solvers" / "common", ROOT / "solvers" / "mobile-android"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import native_image as ni  # noqa: E402
from b241_blobs import FPA64, FPA64_LABELS, JNI64, JNI64_LABELS  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "native_image"
M64 = (1 << 64) - 1
CODE_AT = 0x200                # where a fixture's code sits in its image (the listing's `start`)
DATA_AT = 0x2000               # the writable segment; the x86-64 listing keeps its global at start + 0x1E00
engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")


def need_engine():
    if not ni.UNICORN_AVAILABLE:
        pytest.skip(f"real Unicorn backend unavailable: {ni._ne.UNICORN_UNAVAILABLE_REASON}")


# ------------------------------------------------------------------ a minimal ELF64 shared object
def build_elf(code: bytes, machine: int, *, exports=None, dynamic=(), blob=b"") -> bytes:
    """ET_DYN with a R+X PT_LOAD over the first page (headers, the code at 0x200, the dynamic tables and
    ``blob`` at 0xF00) and a zero-filled RW PT_LOAD at 0x2000.  ``exports`` {name: vaddr} adds a dynamic
    symbol table; ``dynamic`` adds raw (tag, value) entries."""
    assert len(code) <= 0xA00 and len(blob) <= 0x100
    image = bytearray(0x2100)
    image[CODE_AT:CODE_AT + len(code)] = code
    image[0xF00:0xF00 + len(blob)] = blob
    entries = list(dynamic)
    if exports:
        strings = bytearray(b"\0")
        symbols = bytearray(24)
        for name, vaddr in exports.items():
            symbols += struct.pack("<IBBHQQ", len(strings), (1 << 4) | 2, 0, 1, vaddr, 0)
            strings += name.encode() + b"\0"
        image[0xD00:0xD00 + len(symbols)] = symbols
        image[0xE00:0xE00 + len(strings)] = strings
        count = len(symbols) // 24
        image[0xE80:0xE80 + 8 + 4 + 4 * count] = struct.pack("<II", 1, count) + bytes(4 + 4 * count)
        entries += [(6, 0xD00), (5, 0xE00), (10, len(strings)), (11, 24), (4, 0xE80)]
    headers = [struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000),
               struct.pack("<IIQQQQQQ", 1, 6, DATA_AT, DATA_AT, DATA_AT, 0x100, 0x1000, 0x1000)]
    if entries:
        raw = b"".join(struct.pack("<qQ", tag, value) for tag, value in entries) + bytes(16)
        assert len(raw) <= 0x100
        image[0xC00:0xC00 + len(raw)] = raw
        headers.append(struct.pack("<IIQQQQQQ", 2, 4, 0xC00, 0xC00, 0xC00, len(raw), len(raw), 8))
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 3, machine, 1, 0, 0x40, 0,
                             0, 64, 56, len(headers), 64, 0, 0)
    image[0x40:0x40 + 56 * len(headers)] = b"".join(headers)
    return bytes(image)


def x86(label):
    return CODE_AT + JNI64_LABELS[label]


def a64(label):
    return CODE_AT + FPA64_LABELS[label]


@pytest.fixture(scope="module")
def images():
    return {"x86-64": (ni.load(build_elf(JNI64, ni.EM_X86_64)), x86),
            "arm64": (ni.load(build_elf(FPA64, ni.EM_AARCH64)), a64)}


def f32(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def f64(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def test_the_fixture_code_is_the_listing():
    capstone = pytest.importorskip("capstone")
    x = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    a = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    def reads(decoder, blob, labels, label, count):
        return [i.mnemonic for i in decoder.disasm(blob[labels[label]:labels[label] + 64], 0)][:count]

    assert reads(x, JNI64, JNI64_LABELS, "f_add", 2) == ["addss", "ret"]
    assert reads(x, JNI64, JNI64_LABELS, "d_mul", 2) == ["mulsd", "ret"]
    assert reads(x, JNI64, JNI64_LABELS, "mix", 7) == ["cvtsi2sd", "cvtss2sd", "addsd", "cvtsi2sd", "addsd",
                                                      "addsd", "ret"]
    assert reads(x, JNI64, JNI64_LABELS, "f_upper", 2) == ["pshufd", "ret"]
    assert reads(x, JNI64, JNI64_LABELS, "f_rsqrt", 2) == ["rsqrtss", "ret"]
    assert reads(x, JNI64, JNI64_LABELS, "i_fsin", 3) == ["fldz", "fsin", "fstp"]
    assert reads(a, FPA64, FPA64_LABELS, "f_add", 2) == ["fadd", "ret"]
    assert reads(a, FPA64, FPA64_LABELS, "mix", 7) == ["scvtf", "fcvt", "fadd", "scvtf", "fadd", "fadd", "ret"]
    assert reads(a, FPA64, FPA64_LABELS, "f_upper", 2) == ["mov", "ret"]
    # the slot numbers the x86-64 listing calls through are the engine's (jni.h order)
    for name, slot in (("FindClass", 6), ("PushLocalFrame", 19), ("PopLocalFrame", 20), ("NewGlobalRef", 21),
                       ("DeleteGlobalRef", 22), ("DeleteLocalRef", 23), ("IsSameObject", 24), ("NewLocalRef", 25),
                       ("EnsureLocalCapacity", 26), ("GetStringUTFLength", 168), ("MonitorEnter", 217),
                       ("MonitorExit", 218), ("GetJavaVM", 219), ("NewWeakGlobalRef", 226),
                       ("DeleteWeakGlobalRef", 227), ("GetObjectRefType", 232)):
        assert ni.JNI_INDEX[name] == slot, name
        assert name in ni.JNI_MODELLED
    assert ni.VM_SLOTS.index("GetEnv") == 6


# ================================================================== float JNI
@engine
@pytest.mark.parametrize("arch", ["x86-64", "arm64"])
def test_float_and_double_arguments_and_returns(images, arch):
    need_engine()
    img, at = images[arch]
    r = ni.call_jni(img, None, [("F", 1.5), ("F", 2.25)], "F", entry=at("f_add"))
    assert (r.kind, r.value) == ("float", f32(3.75)) and ni.fp_value("F", r.value) == 3.75
    # a bit pattern (how a Dalvik register holds a float) is taken as it is
    r = ni.call_jni(img, None, [("F", f32(-0.5)), ("F", f32(0.125))], "F", entry=at("f_add"))
    assert r.value == f32(-0.375)
    r = ni.call_jni(img, None, [("D", 1.1), ("D", 3.0)], "D", entry=at("d_mul"))
    assert (r.kind, r.value) == ("double", f64(1.1 * 3.0))
    # integer and floating-point arguments interleaved: each class fills its own registers in order
    r = ni.call_jni(img, None, [("I", 3), ("F", 1.5), ("J", -10), ("D", 0.25)], "D", entry=at("mix"))
    assert ni.fp_value("D", r.value) == -5.25
    r = ni.call_jni(img, None, [("I", -7), ("F", 0.5), ("J", 1 << 40), ("D", 2.0)], "D", entry=at("mix"))
    assert ni.fp_value("D", r.value) == -7 + 0.5 + (1 << 40) + 2.0
    assert ni.call_jni(img, None, [("F", 2.9)[:1] + (f32(2.9),)], "I", entry=at("f_to_int")).value == 2
    assert ni.call_jni(img, None, [("F", f32(-2.9))], "I", entry=at("f_to_int")).value == -2
    r = ni.call_jni(img, None, [("I", 7)], "F", entry=at("int_to_f"))
    assert (r.kind, r.value) == ("float", f32(7.0))
    # an infinity is a value; only a NaN is the processor's
    r = ni.call_jni(img, None, [("F", 1.0)], "F", entry=at("f_inf"))
    assert r.value == 0x7F800000


@engine
@pytest.mark.parametrize("arch", ["x86-64", "arm64"])
def test_what_the_abi_leaves_undefined_in_a_vector_register_declines(images, arch):
    need_engine()
    img, at = images[arch]
    for label, jargs, ret in (("f_upper", [("F", 1.0)], "F"),        # the bits above a float argument
                              ("d_upper", [("D", 1.0)], "D"),        # the bits above a double argument
                              ("f_unset", [("F", 1.0)], "F")):       # a register no argument was passed in
        with pytest.raises(ni.EmulationError, match="two runs disagree"):
            ni.call_jni(img, None, jargs, ret, entry=at(label))
    with pytest.raises(ni.EmulationError, match="NaN"):
        ni.call_jni(img, None, [("F", 1.0)], "F", entry=at("f_nan"))
    # the same code read as an int return is not a float result: the NaN rule is the float return's
    assert ni.call_jni(img, None, [("F", 2.0)], "I", entry=at("f_to_int")).value == 2


@engine
def test_processor_chosen_x86_float_instructions_decline(images):
    need_engine()
    img, at = images["x86-64"]
    with pytest.raises(ni.EmulationError, match="rsqrtss executed"):
        ni.call_jni(img, None, [("F", 4.0)], "F", entry=at("f_rsqrt"))
    with pytest.raises(ni.EmulationError, match="fsin executed"):
        ni.call_jni(img, None, [], "I", entry=at("i_fsin"))
    assert {"rsqrtss", "rcpss", "fsin", "fyl2x"} <= ni._X86_FP_INEXACT
    assert not ni._X86_FP_INEXACT & {"sqrtss", "addss", "divsd", "fsqrt"}     # exact by IEEE 754: they run


@engine
def test_more_than_eight_float_arguments_and_bad_values_are_setup_errors(images):
    need_engine()
    img, at = images["x86-64"]
    nine = [("F", 1.0)] * 9
    with pytest.raises(ni.SetupError, match="more than 8 floating-point arguments"):
        ni.call_jni(img, None, nine, "V", entry=at("f_ninth"))
    assert ni.call_jni(img, None, nine[:8], "V", entry=at("f_ninth")).kind == "void"
    for bad in (("F", 0.1), ("F", 1 << 32), ("F", -1), ("D", True), ("D", "1.0"), ("F", 1e300), ("D", 1 << 64)):
        with pytest.raises(ni.SetupError):
            ni.call_jni(img, None, [bad], "V", entry=at("f_ninth"))


def test_fp_bits_and_fp_value():
    assert ni.fp_bits("F", 1.0) == 0x3F800000 and ni.fp_bits("D", 1.0) == 0x3FF0000000000000
    assert ni.fp_bits("F", 0x3F800000) == 0x3F800000                       # an int is the pattern itself
    assert ni.fp_bits("F", float("inf")) == 0x7F800000
    assert ni.fp_bits("F", float("nan")) & 0x7F800000 == 0x7F800000
    assert ni.fp_value("F", 0xC0490FDB) == struct.unpack("<f", struct.pack("<I", 0xC0490FDB))[0]
    assert ni.fp_value("D", ni.fp_bits("D", -2.5)) == -2.5
    assert ni._fp_is_nan("F", 0x7FC00000) and ni._fp_is_nan("F", 0xFF800001)
    assert not ni._fp_is_nan("F", 0x7F800000) and not ni._fp_is_nan("F", 0x3F800000)
    assert ni._fp_is_nan("D", 0x7FF8000000000000) and not ni._fp_is_nan("D", 0x7FF0000000000000)


# ================================================================== the JNI reference lifecycle
def jni(img, label, jargs, ret="I", **kw):
    return ni.call_jni(img, None, jargs, ret, entry=x86(label), **kw)


@engine
def test_reference_kinds_and_identity(images):
    need_engine()
    img, _ = images["x86-64"]
    # type(local) + 10*type(global) + 100*type(weak) + 1000*type(NULL) = 1 + 20 + 300 + 0
    assert jni(img, "ref_types", [("str", "x")]).value == 321
    # same(s, global(s)) + 10*same(s, t) + 100*same(NULL, NULL) + 1000*same(s, NULL)
    assert jni(img, "same", [("str", "a"), ("str", "b")]).value == 101
    assert jni(img, "ensure_ok", [("str", "x")]).value == 5
    assert jni(img, "get_vm", [("str", "x")]).value == 1                   # GetJavaVM's VM hands back this env


@engine
def test_local_frames_free_what_was_created_inside_them(images):
    need_engine()
    img, _ = images["x86-64"]
    assert jni(img, "frame_keep", [("str", "hello")]).value == 5           # the popped frame's result survives
    assert jni(img, "frame_outer", [("str", "abc")]).value == 3            # a reference from before the frame
    with pytest.raises(ni.EmulationError, match="not a live handle"):
        jni(img, "frame_dead", [("str", "hello")])                         # it died with its frame
    with pytest.raises(ni.EmulationError, match="capacity ART versions answer differently"):
        jni(img, "push_big", [("str", "x")])
    with pytest.raises(ni.EmulationError, match="PopLocalFrame without a PushLocalFrame"):
        jni(img, "pop_only", [("str", "x")])


@engine
def test_weak_references_need_a_promotion_and_a_live_strong_reference(images):
    need_engine()
    img, _ = images["x86-64"]
    assert jni(img, "weak_promote", [("str", "hey!")]).value == 4
    with pytest.raises(ni.EmulationError, match="weak global reference"):
        jni(img, "weak_use", [("str", "hey!")])
    with pytest.raises(ni.EmulationError, match="nothing else holds"):
        jni(img, "weak_orphan", [("str", "hey!")], ret="obj")


@engine
def test_monitors_must_balance_and_deletes_must_match_the_reference_kind(images):
    need_engine()
    img, _ = images["x86-64"]
    assert jni(img, "monitor_ok", [("str", "x")]).value == 7
    with pytest.raises(ni.EmulationError, match="holding a JNI monitor"):
        jni(img, "monitor_leak", [("str", "x")])
    with pytest.raises(ni.EmulationError, match="does not hold"):
        jni(img, "monitor_exit_only", [("str", "x")])
    with pytest.raises(ni.EmulationError, match="not a local reference"):
        jni(img, "del_local_of_global", [("str", "x")], ret="V")
    with pytest.raises(ni.EmulationError, match="not a live global reference"):
        jni(img, "del_global_of_local", [("str", "x")], ret="V")


@engine
def test_a_returned_weak_reference_and_frames_past_the_cap_decline(images):
    need_engine()
    img, _ = images["x86-64"]
    with pytest.raises(ni.EmulationError, match="returned a weak global reference"):
        jni(img, "weak_return", [("str", "x")], ret="obj")
    # MAX_LOCAL_FRAMES nested frames are followed (ART pops them at the return); one more is not
    assert jni(img, "push_deep", [("I", ni.MAX_LOCAL_FRAMES)]).value == 9
    with pytest.raises(ni.EmulationError, match="PushLocalFrame nested deeper than the model follows"):
        jni(img, "push_deep", [("I", ni.MAX_LOCAL_FRAMES + 1)])


@engine
def test_a_load_phase_that_keeps_a_monitor_declines():
    need_engine()
    held = ni.load(build_elf(JNI64, ni.EM_X86_64, exports={"JNI_OnLoad": x86("JNI_OnLoad_monitor")}))
    with pytest.raises(ni.EmulationError, match="the load phase returned holding a JNI monitor"):
        ni.load_info(held, classes=("a/B",))
    with pytest.raises(ni.EmulationError, match="the load phase returned holding a JNI monitor"):
        jni(held, "use_loaded", [("str", "x")], classes=("a/B",))


@engine
def test_a_global_reference_from_jni_onload_lives_on_into_calls():
    need_engine()
    img = ni.load(build_elf(JNI64, ni.EM_X86_64, exports={"JNI_OnLoad": x86("JNI_OnLoad")}))
    info = ni.load_info(img, classes=("a/B",))
    assert info == {"load_code": True, "version": 0x10006, "registered": {}}
    # type(global) + 10*same(g, g): the reference JNI_OnLoad stored is live and global in the call
    assert jni(img, "use_loaded", [("str", "x")], classes=("a/B",)).value == 12
    with pytest.raises(ni.EmulationError, match="the load phase created"):
        jni(img, "del_loaded", [("str", "x")], ret="V", classes=("a/B",))
    with pytest.raises(ni.EmulationError, match="FindClass"):
        jni(img, "use_loaded", [("str", "x")])                             # the class is not the delivery's


@engine
def test_reference_values_carry_arts_kind_bits_in_one_layout_only():
    need_engine()
    img = ni.load(build_elf(JNI64, ni.EM_X86_64))
    seen = {}
    for layout in (0, 1):
        run = ni._Run(img, layout, 1000, 1000)
        seen[layout] = [run.new_handle(object(), kind) & 3 for kind in ("local", "global", "weak")]
        handles = [run.new_handle(object(), kind) for kind in ("local", "global", "weak", "global")]
        assert len(set(handles)) == 4                                      # the kind bits never merge two
    assert seen[0] == [0, 0, 0] and seen[1] == [1, 2, 3]                   # ART: local 01, global 10, weak 11


# ================================================================== APS2 packed relocations
def sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        last = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte | (0 if last else 0x80))
        if last:
            return bytes(out)


def numbers(*values: int) -> bytes:
    return b"".join(sleb(v) for v in values)


def aps2_image(blob: bytes, size=None, tag=0x60000011):
    return build_elf(b"\xc3", ni.EM_X86_64,
                     dynamic=[(tag, 0xF00), (0x60000012, len(blob) if size is None else size)], blob=blob)


def test_aps2_groups_decode_to_the_rows_bionic_applies():
    blob = (b"APS2" + numbers(6, 0x2000)
            # three RELATIVE relocations: one r_info, one offset delta (8), each its own addend delta
            + numbers(3, 1 | 2 | 8, 8, 8) + numbers(0x100, 0x10, -8)
            # two GLOB_DAT against symbol 3: one r_info, own offset deltas, no addend (it resets to 0)
            + numbers(2, 1, (3 << 32) | 6) + numbers(0x20, 0x100)
            # one R_X86_64_64 against symbol 2: own offset and info, the group's addend delta (-5 from 0)
            + numbers(1, 8 | 4, -5) + numbers(8, (2 << 32) | 1)
            + b"\0\0")                                           # lld's padding: ignored
    img = ni.load(aps2_image(blob))
    assert img.relocs == [
        (0x2008, 8, 0, 0x100, False), (0x2010, 8, 0, 0x110, False), (0x2018, 8, 0, 0x108, False),
        (0x2038, 6, 3, 0, False), (0x2138, 6, 3, 0, False),
        (0x2140, 1, 2, -5, False)]
    assert img.problem is None
    assert img.plan[:3] == [(0x2008, "rel", 0x100), (0x2010, "rel", 0x110), (0x2018, "rel", 0x108)]


def test_aps2_addends_accumulate_across_groups_and_offsets_may_step_back():
    blob = (b"APS2" + numbers(4, 0x2100)
            + numbers(2, 8 | 4 | 1, 8, 0x40) + numbers(-0x10, -0x10)       # r_info 8, addend 0x40 for both
            + numbers(2, 8 | 1, 8) + numbers(0x30, 1, 8, 2))               # +1, then +2 on the running addend
    img = ni.load(aps2_image(blob))
    assert img.relocs == [(0x20F0, 8, 0, 0x40, False), (0x20E0, 8, 0, 0x40, False),
                          (0x2110, 8, 0, 0x41, False), (0x2118, 8, 0, 0x43, False)]


MALFORMED_APS2 = [
    (b"APS1" + numbers(0, 0), None, "header"),                               # not the APS2 magic
    (b"APS2" + numbers(2, 0x2000) + numbers(2, 1 | 2 | 8, 8, 8, 1), None, "truncated"),   # one addend short
    (b"APS2" + numbers(ni.MAX_RELOCS + 1, 0x2000), None, "too many relocations"),
    (b"APS2" + b"\x80" * 11 + b"\x00", None, "longer than 64 bits"),
    (b"APS2", 3, "table size"),
]


@pytest.mark.parametrize("blob,size,reason", MALFORMED_APS2)
def test_malformed_aps2_is_an_image_problem(blob, size, reason):
    img = ni.load(aps2_image(blob, size=size))
    assert img.problem.startswith("Android packed relocations: ") and reason in img.problem
    assert img.relocs == []                                    # no half-decoded row is applied


@engine
@pytest.mark.parametrize("blob,size,reason", MALFORMED_APS2)
def test_an_image_with_malformed_aps2_is_never_run(blob, size, reason):
    need_engine()
    raw = aps2_image(blob, size=size)
    with pytest.raises(ni.SetupError, match=reason):           # the function was not run: a setup error
        ni.call_jni(ni.load(raw), None, [], "V", entry=CODE_AT)
    with pytest.raises(ni.EmulationError, match=reason):
        ni.emulate_symbol(raw, CODE_AT, [])


@engine
def test_dt_android_rel_in_a_64_bit_image_is_an_image_problem():
    need_engine()
    blob = b"APS2" + numbers(0, 0)
    img = ni.load(aps2_image(blob, tag=0x6000000F))
    assert "DT_ANDROID_REL" in img.problem
    with pytest.raises(ni.EmulationError, match="DT_ANDROID_REL"):
        ni.emulate_symbol(aps2_image(blob, tag=0x6000000F), CODE_AT, [])


# ---- the committed KB-2 fixture with its DT_RELA table re-packed as APS2 runs to the same values
SBOX = (0x3, 0x1, 0x4, 0x1, 0x5, 0x9, 0x2, 0x6, 0x5, 0x3, 0x5, 0x8, 0x9, 0x7, 0x9, 0x3)
FNV, SEED = 0x100000001B3, 0x9E3779B97F4A7C15
WORDS = ("alpha", "bravo", "charlie", "delta")
MIX = "Java_com_huntress_kb2_NativeLab_mixString"


def model_mix_string(text: str) -> int:
    """tests/fixtures/native_image/SOURCES.c, Java_..._mixString, in Python."""
    raw = text.encode()
    h = SEED
    for byte in raw[:47]:
        h = ((h ^ byte) * FNV) & M64
    for i in range(len(raw) & 31):
        h = ((h ^ SBOX[i & 15]) * FNV) & M64
    h = (h + len(WORDS[len(raw) & 3])) & M64
    return (h * 0x9E3779B97F4A7C15) & M64 if len(raw) & 1 else ((h << 13) | (h >> 51)) & M64


def repack_as_aps2(so: bytes, style: str) -> bytes:
    """`so` with its DT_RELA table rewritten in place as an APS2 stream and its tags renamed."""
    img = ni.load(so)
    rela, size = img.dyn[7][0], img.dyn[8][0]
    seg = next(s for s in img.loads if s[0] <= rela < s[0] + s[2])
    at = seg[3] + rela - seg[0]
    rows = [struct.unpack_from("<QQq", so, at + 24 * k) for k in range(size // 24)]
    out = bytearray(b"APS2" + numbers(len(rows), 0))
    offset = addend = 0
    if style == "flat":                                     # one group, nothing shared
        out += numbers(len(rows), 8)
        for r_offset, r_info, r_addend in rows:
            out += numbers(r_offset - offset, r_info, r_addend - addend)
            offset, addend = r_offset, r_addend
    else:                                                   # runs sharing r_info (as lld groups RELATIVE)
        k = 0
        while k < len(rows):
            n = k
            while n < len(rows) and rows[n][1] == rows[k][1]:
                n += 1
            out += numbers(n - k, 1 | 8, rows[k][1])
            for r_offset, _info, r_addend in rows[k:n]:
                out += numbers(r_offset - offset, r_addend - addend)
                offset, addend = r_offset, r_addend
            k = n
    assert len(out) <= size, "the packed table must fit where the plain one was"
    patched = bytearray(so)
    patched[at:at + size] = bytes(out) + bytes(size - len(out))
    dyn_va, dyn_size = img.dynamic
    dseg = next(s for s in img.loads if s[0] <= dyn_va < s[0] + s[2])
    dyn_at = dseg[3] + dyn_va - dseg[0]
    renamed = 0
    for k in range(dyn_size // 16):
        tag, value = struct.unpack_from("<qQ", patched, dyn_at + 16 * k)
        new = {7: (0x60000011, value), 8: (0x60000012, len(out)), 9: (21, 0), 0x6FFFFFF9: (21, 0)}.get(tag)
        if new:
            struct.pack_into("<qQ", patched, dyn_at + 16 * k, *new)
            renamed += 1
    assert renamed >= 3
    return bytes(patched)


@engine
@pytest.mark.parametrize("name", ["kb2_jni_x86_64.so", "kb2_jni_arm64.so"])
@pytest.mark.parametrize("style", ["flat", "grouped"])
def test_a_real_library_repacked_as_aps2_relocates_and_runs_the_same(name, style):
    need_engine()
    so = (FX / name).read_bytes()
    plain = ni.load(so)
    packed = ni.load(repack_as_aps2(so, style))
    assert packed.problem is None and 7 not in packed.dyn and 0x60000011 in packed.dyn
    assert packed.relocs == plain.relocs and len(plain.relocs) > 8
    assert packed.plan == plain.plan
    for text in ("", "a", "hello world", "x" * 31):
        got = ni.call_jni(packed, MIX, [("str", text)], "J")
        assert got.kind == "int" and got.value == model_mix_string(text), text
        assert ni.call_jni(plain, MIX, [("str", text)], "J").value == got.value


# ================================================================== the mobile bridge passes floats on
def test_bridge_maps_float_and_double_arguments_to_bit_patterns():
    import native_image_bridge as bridge

    class Box:
        def __init__(self, v):
            self.v = v

    mod = types.SimpleNamespace(_Box=Box, _Str=type("Str", (), {}))

    def vm(shorty):
        return types.SimpleNamespace(dex=types.SimpleNamespace(meth_shorty=lambda midx: shorty))

    one = f32(1.0)
    # static (F, D, I): the double takes two argument registers, so the int is the fourth word
    got = bridge._java_args(vm("VFDI"), 0, [one, f64(2.5), 0, 9], None, True, mod)
    assert got == [("F", one), ("D", f64(2.5)), ("I", 9)]
    # a register holds a float sign-extended or not: the pattern is its low 32 bits
    assert bridge._java_args(vm("VF"), 0, [f32(-1.0) - (1 << 32)], None, True, mod) == [("F", f32(-1.0))]
    assert bridge._java_args(vm("VF"), 0, [Box(one)], None, True, mod) == [("F", one)]
    assert bridge._java_args(vm("VF"), 0, ["text"], None, True, mod) is None
    assert bridge._java_args(vm("VD"), 0, [True], None, True, mod) is None
    # an instance method: `this` is the first word
    assert bridge._java_args(vm("VF"), 0, [object(), one], None, False, mod) == [("F", one)]


def test_bridge_run_returns_a_float_result_and_zero_is_the_denied_sentinel(monkeypatch):
    import native_image_bridge as bridge

    class Box:
        def __init__(self, v):
            self.v = v

    module = types.ModuleType("b241_fake_vm")
    module._Box, module._Str = Box, type("Str", (), {})
    monkeypatch.setitem(sys.modules, module.__name__, module)
    FakeVM = type("FakeVM", (), {"__module__": module.__name__})
    vm = FakeVM()
    vm.dex = types.SimpleNamespace(meth_shorty=lambda midx: "FF")
    seen = []

    def evaluate(vm_, target, jargs, ret, static, bundle):
        seen.append((jargs, ret, static))
        return ("float", f32(3.5), {}, None)

    monkeypatch.setattr(bridge, "_evaluate", evaluate)
    target = types.SimpleNamespace(ident=("lib", "sym"))
    bundle = types.SimpleNamespace(memo={})
    op = next(iter(bridge.STATIC_OPS))
    out = bridge._run(vm, 0, [f32(1.5)], None, op, target, bundle, "F")
    assert out[:2] == ("float", f32(3.5))
    assert seen == [([("F", f32(1.5))], "F", True)]


class Declined(Exception):
    pass


def _decline(message):
    return Declined(message)


@pytest.mark.parametrize("kind,shorty", [("float", "F"), ("double", "D")])
def test_bridge_invoke_reads_a_whole_image_plus_zero_as_the_denied_sentinel(monkeypatch, kind, shorty):
    """invoke() never answers a float or double whose bits are all zero (+0.0) from the whole image: like an
    integer 0 it is the gate-FAIL leg's sentinel. -0.0 and any other value are readings."""
    import native_image_bridge as bridge

    target = types.SimpleNamespace(how="registered", decline=None, pr=None, calls=[1], image_ok=True, flags=set(),
                                   unasked=set(), call_bodies=[], extra=[], abi32_only=False, ident=("lib", "sym"))
    bundle = types.SimpleNamespace(target=lambda vm, op, midx: target, memo={})
    answers = []
    monkeypatch.setattr(bridge, "_run", lambda *a: answers[-1])

    def invoke(bits):
        answers.append((kind, bits, [], {}, None))
        vm = types.SimpleNamespace(native_images=bundle,
                                   dex=types.SimpleNamespace(meth_shorty=lambda midx: shorty + shorty))
        legacy = lambda *a: pytest.fail("the legacy reader is not asked for a registered native")  # noqa: E731
        return bridge.invoke(vm, next(iter(bridge.STATIC_OPS)), 0, [0], legacy, _decline), vm

    with pytest.raises(Declined, match="denied sentinel"):
        invoke(0)
    negative_zero = f32(-0.0) if kind == "float" else f64(-0.0)
    for bits in (negative_zero, f32(1.5) if kind == "float" else f64(1.5)):
        value, vm = invoke(bits)
        assert value == bits and bridge.ROUTE_IMAGE in vm._kb2_flags
    with pytest.raises(Declined, match="denied sentinel"):    # the int sentinel, for comparison
        answers.append(("int", 0, [], {}, None))
        bridge.invoke(types.SimpleNamespace(native_images=bundle,
                                            dex=types.SimpleNamespace(meth_shorty=lambda midx: "II")),
                      next(iter(bridge.STATIC_OPS)), 0, [0], None, _decline)
