#!/usr/bin/env python3
"""KB-2 (Day 27 build): whole-image native emulation for the Mobile dex chain, and the Binary-lane API.

Covers solvers/common/native_image.py (the engine) and solvers/mobile-android/native_image_bridge.py (the dex
VM's bridge, wired into dex_chain_codec.VM._invoke / answer()):

  A. the engine on honest clang-built fixtures (tests/fixtures/native_image, built by
     tests/native_image_fixtures.py; x86-64 and AArch64, plus a section-stripped copy): sibling calls through
     the PLT, .rodata tables, .data through the GOT, RELATIVE pointer tables, an ABS64 pointer to an import,
     a switch jump table, the libc subset and the JNIEnv (String, byte[], int[] in and out) -- every value
     checked against an INDEPENDENT Python model;
  B. the JNI function-table layout checked against the offsets clang compiled from the JDK's own jni.h;
  C. adversarial decoys: each must DECLINE (EmulationError), never return a value;
  D. the real saved libraries (Days 16, 23-26): whole image == hand-rolled reader == single-function engine;
     the Day-16 PLT sibling call that the single-function engine cannot follow;
  E. relocation strictness on patched images (APS2, TEXTREL, an unapplied RELATIVE, libc interposition);
  F. the Binary API emulate_symbol (ints, bytes in/out, vaddr, local .symtab symbol, cstr, ET_EXEC);
  G. dex-chain integration: a code that needs the whole image is answered ONLY as an unsure pick under the
     new key mobile.codec/analysis+native-image (+native-cstr for the C-pointer shortcut), never plain, even
     with the real ledger; legacy-proven natives answer exactly as before; multi-library disagreement, a
     foreign library, the NULL sentinel, a method not declared native and a spinning native all decline;
  H. timing of a call and of a chain;
  I. (r2) the load phase: DT_INIT before DT_INIT_ARRAY, a constructor that decrypts .data and builds a .bss
     table, JNI_OnLoad + RegisterNatives binding a method to a function OTHER than its decoy Java_ export (the
     shipped readers alone answered that decoy plain), constructor-only libraries, and four decoy load phases
     (an unmodelled import, an undeclared registration, a refused version, an unknown class) that decline the
     legacy reading too;
  J. (r2) machine-dependent instructions (rdtsc / cpuid / rdrand / xgetbv; cntvct_el0 / midr_el1 / RNDR /
     ctr_el0) decline in BOTH engines, the newly modelled JNI slots answer exactly, a W+X segment is refused;
  K. (r2) the bridge's size bounds and the native_emulate.emulate_symbol re-export;
  L. (r3, the fixer round of the first adversarial review of e71b954) the call resolved ART's way across every dex
     and up the superclass chain (multidex and a subclass reference to a registered native), the legacy reader
     asked about the EXACT symbol only (a loose decoy and a second class's export), every library binding a name
     agreeing (two bodies of one symbol), the load phase's heap blocks read-only and its local references gone,
     layouts that differ in every address bit a device randomises, pinned vs copied arrays, the demotions
     (+abi-unverified, +ctor-unverified) that replace two regressions, and the budgets (an evaluation cap, a memo,
     image bytes mapped, work inside the libc model).
  M. (fix round 1, the adversarial review of e281f95) codec_search's fall-through: an `analysis` document whose
     dex chain gave no one code never answers the generic search's code in clear plain (end to end, runner-shaped
     files, one and five deliveries, the partial answers too); an unmodelled JNI_OnLoad demotes
     (+onload-unverified@<why>) instead of declining the delivery, liblog modelled (a logging JNI_OnLoad or helper
     library is read exactly), a class defined twice is one class when its definitions agree (+dup-class when
     not); a whole image that RAN a call the legacy reader read and failed declines (an emulator check on the
     legacy engine's fixed code base), one that ran out of work demotes (+image-unchecked@<method>); a boxed
     argument to an Object parameter is an object; a negative jint keeps its sign; Dalvik's compare opcodes;
     a framework call named like an app export; a library the engine refuses that holds the name or a JNI_OnLoad;
     the costs (libraries no call binds are not parsed, a RELR table bounded, a large secondary dex not parsed by
     the bridge, each dex read once) and the process caches (a warm process answers and charges what a cold one
     does).
  N. (fix round 2: the port onto af3dbf7, so-ambig and KB-7 merged, and the adversarial review of 4250749) the
     review's wrong plains as regression checks: a negative native jint used as an array index or size (the VM
     bounds-checks every index as Java does), the image not asked (the 16-evaluation cap, two heavy calls on the
     work totals, a library padded past the size bound, an image problem: each a demotion, +image-unchecked), a
     demotion beside an agreeing pure-Java entry, the long-name framework fall-through (+jni-long when both engines
     read it), the load-phase charge and the zero-range mapping; and the merged native path (so-ambig's binding
     rules gate every bridge reading: two libraries of one machine registering a native, a registration beside an
     exporter, a java/ class native, an undefined class's exact name, a dex after a numbering gap, IRELATIVE).
  Since the port, the checks above that the merged path now answers MORE restrictively (so-ambig declines a
  binding beside a JNI_OnLoad not proven inert, DT_INIT / DT_INIT_ARRAY, two .so bodies of one machine; KB-7
  declines a class two dex members define) say so: "[KB-2 port onto so-ambig: more restrictive]".

Fixtures: tests/fixtures/native_image (rebuild: tests/native_image_fixtures.py; `--load-only` rebuilds only the
r2 ones, kb2_load* and kb2_env*; `--r3-only` the r3 ones, kb2_r3_*; `--fix1-only` the fix-round-1 ones, kb2_f1_*;
`--fix2-only` the fix-round-2 ones, kb2_f2_*).

Run:  .venv/bin/python -I -B tests/test_day27_native_image_mobile.py
"""
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)
import contextlib
import hashlib
import io
import json
import random
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))          # the ctf package (appended: the engine dirs stay first)
from ctf import paths  # noqa: E402
# The saved Huntress attempts (read only), only from $CTF_REAL_CHALLENGES through ctf.paths; never derived from
# this checkout's location. Unset: None and the sections skip; set to a missing folder: FileNotFoundError.
SAVED_ROOT = paths.saved_challenges_root()


def _saved_glob(pattern):
    return sorted(SAVED_ROOT.glob(pattern)) if SAVED_ROOT is not None else []


sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "solvers" / "mobile-android"))
sys.path.insert(0, str(ROOT / "tests"))

import native_image as ni            # noqa: E402
import native_emulate as ne          # noqa: E402
import native_image_bridge as nib    # noqa: E402
import dex_chain_codec as dcc        # noqa: E402
import labels                        # noqa: E402
from day24_mobile_computed_specimens import Asm   # noqa: E402

FX = ROOT / "tests" / "fixtures" / "native_image"
M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF
PASS = 0
FAIL = 0
P = "Java_com_huntress_kb2_NativeLab_"
D = "Java_com_huntress_kb2_Decoy_"
G = "Java_com_huntress_kb2_Gate_"


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name, detail)


def fx(name):
    return (FX / name).read_bytes()


def declines(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except ni.EmulationError:
        return True


def cache_identity_checks():
    """Content-cache safety does not depend on Unicorn being installed."""
    old_image, old_sha1 = ni.ElfImage, hashlib.sha1

    class FakeImage:
        def __init__(self, data):
            self.data = data

    class CollidingSha1:
        def digest(self):
            return b"x" * 20

    try:
        ni._CACHE.clear()
        ni._CACHE_ORDER.clear()
        nib.clear_caches()
        ni.ElfImage = FakeImage
        hashlib.sha1 = lambda *_a, **_k: CollidingSha1()
        one, two = ni.load(b"native-image-one"), ni.load(b"native-image-two")
        d1, d2 = nib._digest(b"bridge-one"), nib._digest(b"bridge-two")
        check("content caches use complete SHA-256 even when SHA-1 is forced to collide",
              one is not two and one.content_digest == hashlib.sha256(one.data).digest()
              and two.content_digest == hashlib.sha256(two.data).digest()
              and d1 == hashlib.sha256(b"bridge-one").digest()
              and d2 == hashlib.sha256(b"bridge-two").digest() and d1 != d2)
    finally:
        hashlib.sha1 = old_sha1
        ni.ElfImage = old_image
        ni._CACHE.clear()
        ni._CACHE_ORDER.clear()
        nib.clear_caches()


# ============================================================================== independent Python models
SBOX = [0x3, 0x1, 0x4, 0x1, 0x5, 0x9, 0x2, 0x6, 0x5, 0x3, 0x5, 0x8, 0x9, 0x7, 0x9, 0x3]
SEED = 0x9E3779B97F4A7C15
FNV = 0x100000001B3
WORDS = ["alpha", "bravo", "charlie", "delta"]


def m_round(x, k):
    for i in range(k):
        x = ((x ^ SBOX[i & 15]) * FNV) & M64
    return x


def m_fold(bs):
    h = SEED
    for b in bs:
        h = ((h ^ b) * FNV) & M64
    return h


def m_mix_string(s):
    p = s.encode()
    n = len(p)
    m = min(n, 47)
    h = m_fold(p[:m])
    h = m_round(h, n & 31)
    h = (h + len(WORDS[n & 3])) & M64
    if n & 1:
        h = (h * 0x9E3779B97F4A7C15) & M64
    else:
        h = ((h << 13) | (h >> 51)) & M64
    return h


def sbytes(bs):
    return [b - 256 if b & 0x80 else b for b in bs]


def m_mix_bytes(arr, key):
    new = [((v & 0xFF) ^ ((key + i) & 0xFF)) for i, v in enumerate(arr)]
    return m_fold(new), sbytes(new)


def m_encode(s):
    p = s.encode()
    h = m_round(m_fold(p), len(p))
    return "ANS-%016X" % h


def m_make_bytes(n, seed):
    x = seed & M64
    out = []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & M64
        out.append(x >> 56)
    return sbytes(out)


def s32(v):
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


def m_sum_ints(arr):
    acc = 0x811C9DC5
    for v in arr:
        acc = ((acc << 5) | (acc >> 27)) & M32
        acc ^= v & M32
    return s32(acc)


def m_region_hash(arr, off, ln):
    tmp = [v & 0xFF for v in arr[off:off + ln]]
    h = m_fold(tmp)
    if ln > 1:
        h ^= 0x5555
    return h


def m_compare(a, b):
    def sign(x, y):
        return (x > y) - (x < y)
    c = sign(a.encode(), b.encode())
    d = sign(a.encode()[:2], b.encode()[:2])
    r = (1 if c < 0 else (2 if c > 0 else 3)) * 10 + (1 if d < 0 else (2 if d > 0 else 3))
    return r * 100 + len(a.encode("utf-16-le")) // 2 + len(b.encode())


def m_wide(a, b, c, d, e, f):
    return (b * 3 + (a & M32) + (c & M32) * 5 + (d & M32) * 7 + (e & M32) * 11 + f * 13) & M64


def m_dispatch(k, x):
    v = x & M64
    k &= 7
    if k == 0:
        v ^= 0x1111
    elif k == 1:
        v = (v + 0x2222222222) & M64
    elif k == 2:
        v = ((v << 7) | (v >> 57)) & M64
    elif k == 3:
        v = (v * 0x5BD1E995) & M64
    elif k == 4:
        v = (v - 0x7777) & M64
    elif k == 5:
        v = (~v) & M64
    elif k == 6:
        v ^= v >> 29
    else:
        v = (v * 9 + 1) & M64
    return v


def m_rc4(arr, key):
    S = list(range(256))
    j = 0
    k = key.encode()
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for v in arr:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append((v & 0xFF) ^ S[(S[i] + S[j]) & 0xFF])
    return sbytes(out)


# ============================================================================== A. the engine on the fixtures
def test_engine_fixtures():
    rnd = random.Random(27)
    for name in ("kb2_jni_x86_64.so", "kb2_jni_arm64.so", "kb2_jni_x86_64_stripped.so"):
        img = ni.load(fx(name))
        tag = name.replace("kb2_jni_", "").replace(".so", "")
        ok = True
        for s in ("", "a", "hello world", "x" * 31, "the quick brown fox jumps over the lazy dog!", "y" * 60):
            r = ni.call_jni(img, P + "mixString", [("str", s)], "J")
            ok &= r.kind == "int" and r.value == m_mix_string(s) and not r.commits
        check("A/%s mixString == model (PLT sibling, .rodata, GOT .data, RELATIVE tables, libc)" % tag, ok)
        ok = True
        for _ in range(4):
            arr = [rnd.randint(-128, 127) for _ in range(rnd.randint(0, 40))]
            key = rnd.randint(-1000, 1000)
            r = ni.call_jni(img, P + "mixBytes", [("arr:B", arr), ("I", key)], "J")
            h, new = m_mix_bytes(arr, key)
            ok &= r.value == h and r.commits.get(0, arr) == new
        check("A/%s mixBytes == model, in-place commit of byte[]" % tag, ok)
        ok = True
        for s in ("seed-value", "", "Ünïcødé-é", "x" * 40):
            r = ni.call_jni(img, P + "encode", [("str", s)], "str")
            ok &= r.kind == "str" and r.value == m_encode(s)
        check("A/%s encode == model (malloc/realloc/strcpy/strchr/strncpy/free, NewStringUTF)" % tag, ok)
        ok = True
        for n, seed in ((0, 1), (12, 0x1234), (64, -5)):
            r = ni.call_jni(img, P + "makeBytes", [("I", n), ("J", seed)], "arr:B")
            ok &= r.kind == "arr" and r.value == m_make_bytes(n, seed) and r.arr_arg is None
        check("A/%s makeBytes == model (NewByteArray, calloc, SetByteArrayRegion)" % tag, ok)
        arr = [1, -2, 3, 0x7FFFFFFF, -(1 << 31)]
        r = ni.call_jni(img, P + "sumInts", [("arr:I", arr)], "I")
        check("A/%s sumInts == model (Get/ReleaseIntArrayElements JNI_ABORT)" % tag,
              r.value == m_sum_ints(arr) and not r.commits)
        data = [rnd.randint(-128, 127) for _ in range(40)]
        ok = all(ni.call_jni(img, P + "regionHash", [("arr:B", data), ("I", o), ("I", ln)], "J").value ==
                 m_region_hash(data, o, ln) for (o, ln) in ((0, 0), (3, 10), (8, 32), (39, 1)))
        check("A/%s regionHash == model (GetByteArrayRegion, ExceptionCheck, memmove, memcmp)" % tag, ok)
        check("A/%s regionHash out of bounds declines (no exception model)" % tag,
              declines(ni.call_jni, img, P + "regionHash", [("arr:B", data), ("I", 30), ("I", 20)], "J"))
        ok = all(ni.call_jni(img, P + "compare", [("str", a), ("str", b)], "I").value == m_compare(a, b)
                 for a, b in (("abcd", "abzz"), ("abc", "abc"), ("b", "a"), ("", "zz"), ("abcé", "ab")))
        check("A/%s compare == model (strcmp via an ABS64 import pointer, strncmp sign only)" % tag, ok)
        r = ni.call_jni(img, P + "wide", [("I", -1), ("J", 2), ("I", 3), ("I", 4), ("I", 5), ("J", 6)], "J")
        check("A/%s wide == model (stack arguments on x86-64)" % tag, r.value == m_wide(-1, 2, 3, 4, 5, 6))
        ok = all(ni.call_jni(img, P + "dispatch", [("I", k), ("J", 0x0123456789ABCDEF)], "J").value ==
                 m_dispatch(k, 0x0123456789ABCDEF) for k in range(-3, 9))
        check("A/%s dispatch == model (switch jump table)" % tag, ok)
        data = [rnd.randint(-128, 127) for _ in range(77)]
        r = ni.call_jni(img, P + "crc32", [("arr:B", data)], "I")
        check("A/%s crc32 == zlib.crc32 (a stack-built table)" % tag,
              (r.value & M32) == zlib.crc32(bytes(v & 0xFF for v in data)))
        r = ni.call_jni(img, P + "rc4", [("arr:B", data), ("str", "Secret")], "V")
        check("A/%s rc4 in place == model (void return, commit)" % tag,
              r.kind == "void" and r.commits.get(0) == m_rc4(data, "Secret"))


def test_engine_determinism():
    img = ni.load(fx("kb2_jni_x86_64.so"))
    a = [ni.call_jni(img, P + "mixString", [("str", "repeat")], "J").value for _ in range(3)]
    check("A/repeat calls are identical (no state carried between calls)", len(set(a)) == 1)
    x = ni.call_jni(img, P + "mixString", [("str", "abc")], "J").value
    y = ni.call_jni(ni.load(fx("kb2_jni_arm64.so")), P + "mixString", [("str", "abc")], "J").value
    check("A/x86-64 and arm64 builds agree", x == y == m_mix_string("abc"))


# ============================================================================== B. JNI table layout vs jni.h
def test_jni_layout():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    img = ni.load(fx("kb2_jni_x86_64.so"))
    dec = ni.load(fx("kb2_decoy_x86_64.so"))

    def disps(im, sym):
        va = im.exports()[sym]
        code = im.file_bytes(va, 1200 if va + 1200 <= im.loads[1][0] + im.loads[1][2] else
                             im.loads[1][0] + im.loads[1][2] - va)
        out = []
        for ins in md.disasm(code, va):
            if ins.mnemonic == "call" and "qword ptr [r" in ins.op_str and "+ 0x" in ins.op_str:
                out.append(int(ins.op_str.split("+ 0x")[1].rstrip("]"), 16))
            if ins.mnemonic == "ret" and out:
                pass
        return out
    used = {}
    for sym in (P + "mixString", P + "mixBytes", P + "encode", P + "makeBytes", P + "sumInts", P + "regionHash",
                P + "compare"):
        for d in disps(img, sym):
            used.setdefault(d // 8, set()).add(sym.rsplit("_", 1)[1])
    names = {ni.JNI_SLOTS[i] for i in used}
    want = {"GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "GetByteArrayElements",
            "ReleaseByteArrayElements", "GetStringUTFLength", "NewStringUTF", "NewByteArray", "SetByteArrayRegion",
            "GetIntArrayElements", "ReleaseIntArrayElements", "GetByteArrayRegion", "ExceptionCheck",
            "GetStringLength"}
    check("B/every JNI slot clang compiled from jni.h maps to the modelled function of that name",
          names == want, "%s vs %s" % (sorted(names), sorted(want)))
    fc = disps(dec, D + "findClass")
    check("B/FindClass is slot 6 in compiled code too", fc and ni.JNI_SLOTS[fc[0] // 8] == "FindClass")


# ============================================================================== C. adversarial decoys
DECOYS = [("unmodelledImport", [("J", 5)], "J"), ("findClass", [("J", 5)], "J"), ("uninitStack", [("J", 5)], "J"),
          ("classValue", [("J", 5)], "J"), ("envValue", [("J", 5)], "J"), ("returnsAddr", [("J", 5)], "J"),
          ("spin", [("J", 5)], "J"), ("counter", [("J", 5)], "J"), ("smash", [("J", 5)], "J"),
          ("useAfterFree", [("J", 5)], "J"), ("writeRodata", [("J", 5)], "J"), ("libcData", [("J", 5)], "J"),
          ("mallocZero", [("J", 5)], "J"), ("memcmpMagnitude", [("str", "abc"), ("str", "abd")], "I"),
          ("isCopy", [("arr:B", [1, 2])], "I"), ("noRelease", [("arr:B", [1, 2])], "I"),
          ("abortModified", [("arr:B", [1, 2])], "I"), ("badRegion", [("arr:B", [1, 2, 3])], "J"),
          ("sysc", [("J", 5)], "J"), ("crcLazy", [("I", 3)], "I")]


def test_decoys():
    for abi in ("x86_64", "arm64"):
        img = ni.load(fx("kb2_decoy_%s.so" % abi))
        for name, ja, rt in DECOYS:
            t = time.perf_counter()
            dec = declines(ni.call_jni, img, D + name, ja, rt)
            check("C/%s %s declines (%.0f ms)" % (abi, name, 1000 * (time.perf_counter() - t)), dec)
        r = ni.call_jni(img, D + "nativeEvidence", [("I", 0x197DE)], "str")
        check("C/%s a jstring that is a C pointer is reported as kind cstr (never as a JNI string)" % abi,
              r.kind == "cstr" and r.value == "ANS-0F899F2B0D6E5B4B")
        r = ni.call_jni(img, D + "nullStr", [("I", 5)], "str")
        check("C/%s a NULL return is kind null" % abi, r.kind == "null")
        check("C/%s a wrong argument kind declines" % abi,
              declines(ni.call_jni, img, D + "isCopy", [("arr:B", [1, 300])], "I"))
        check("C/%s an unknown symbol declines" % abi, declines(ni.call_jni, img, D + "nope", [], "J"))
    shared = [1, 2, 3]
    check("C/one Java array passed as two arguments (aliasing) declines",
          declines(ni.call_jni, fx("kb2_jni_x86_64.so"), P + "rc4", [("arr:B", shared), ("arr:B", shared)], "V")
          and shared == [1, 2, 3])


# ============================================================================== D. real saved libraries
def _saved_so(day_glob):
    for apk in _saved_glob(day_glob):
        with zipfile.ZipFile(apk) as zf:
            for n in zf.namelist():
                if n.endswith(".so"):
                    return zf.read(n)
    return None


def test_real_libraries():
    real = [("day-23/mobile-android-*/mastery/artifact/delivery-05/*.apk", "NativeLibrarySecrets_nativeShare", 1),
            ("day-24/mobile-android-*/mastery/artifact/delivery-05/*.apk", "NativeLibrarySecrets_nativeShare", 1),
            ("day-25/mobile-android-*/mastery/artifact/delivery-06/*.apk", "JNIBoundary_nativeShare", 2),
            ("day-26/mobile-android-*/mastery/artifact/delivery-06/*.apk", "JNIBoundary_nativeShare", 2)]
    rnd = random.Random(5)
    seen = 0
    for glob_, suffix, nargs in real:
        so = _saved_so(glob_)
        if so is None:
            print("SKIP D/%s (saved APK absent)" % glob_.split("/")[0])
            continue
        seen += 1
        img = ni.load(so)
        sym = next(s for s in img.exports() if s.endswith(suffix))
        code = dcc._parse_so(so)[sym][1]
        ok = True
        for _ in range(6):
            seed = rnd.getrandbits(64)
            jargs = [("J", seed)]
            iargs = [0, 0, seed]
            if nargs == 2:
                gate = struct.unpack("<I", code[code.index(b"\x81\xfe") + 2:][:4])[0] if b"\x81\xfe" in code else 0
                ln = (1 << 16) | gate if rnd.random() < 0.7 else rnd.getrandbits(16)
                jargs.append(("I", ln))
                iargs.append(ln)
            whole = ni.call_jni(img, sym, jargs, "J").value
            try:
                hand = dcc._emulate_x86(code, iargs) & M64
            except dcc._Decline:
                hand = None
            single = ne.emulate_x86_sysv(code, iargs) & M64
            ok &= whole == single and (hand is None or hand == whole)
        check("D/%s whole image == single-function engine == hand-rolled reader" % glob_.split("/")[0], ok)
    so16 = _saved_so("day-16/mobile-android-*/mastery/artifact/delivery-05/*.apk")
    if so16 is not None:
        img = ni.load(so16)
        sym = next(s for s in img.exports() if s.endswith("nativeEvidence"))
        r = ni.call_jni(img, sym, [("I", 0x10000)], "str")
        check("D/day-16 nativeEvidence: PLT call to a sibling + .rodata C string (cstr)",
              r.kind == "cstr" and dcc.ANSWER.fullmatch(r.value or "") is not None)
        code = dcc._parse_so(so16)[sym][1]
        check("D/day-16 the single-function engine cannot follow that call (why the whole image exists)",
              declines(ne.emulate_x86_sysv, code, [0, 0, 0x10000]))
    if not seen:
        print("SKIP D (no saved native APKs)")


# ============================================================================== E. relocation strictness
def _patch_dyn_tag(so, old_tag, new_tag):
    img = ni.load(so)
    va, sz = img.dynamic
    off = next(o for (v, m, fs, o, fl) in img.loads if v <= va < v + fs) + va - \
        next(v for (v, m, fs, o, fl) in img.loads if v <= va < v + fs)
    b = bytearray(so)
    for k in range(sz // 16):
        tag = struct.unpack_from("<q", b, off + 16 * k)[0]
        if tag == old_tag:
            struct.pack_into("<q", b, off + 16 * k, new_tag)
            return bytes(b)
    raise AssertionError("tag not found")


def test_relocation_strictness():
    so = fx("kb2_jni_x86_64.so")
    # B-241: a well-formed APS2 table is decoded now (tests/test_b241_native_image.py); this DT_ANDROID_RELA names
    # no table (it is DT_RELACOUNT's count read as an address), which is still an image problem
    aps2 = ni.load(_patch_dyn_tag(so, 0x6FFFFFF9, 0x60000011))
    check("E/an image with Android APS2 packed relocations declines as a whole",
          aps2.problem and declines(ni.call_jni, aps2, P + "mixString", [("str", "a")], "J"))
    tr = ni.load(_patch_dyn_tag(so, 0x6FFFFFF9, 22))
    check("E/an image with text relocations declines as a whole",
          tr.problem and declines(ni.call_jni, tr, P + "mixString", [("str", "a")], "J"))
    # an unapplied RELATIVE: retype the kb2_words entries to IRELATIVE -> their slots are poisoned
    img = ni.load(so)
    words_va = next(s.value for s in img.dynsyms if s.name == "kb2_words")
    rela = img.dyn[7][0]
    relasz = img.dyn[8][0]
    base_off = next(o - v for (v, m, fs, o, fl) in img.loads if v <= rela < v + fs)
    b = bytearray(so)
    n = 0
    for k in range(relasz // 24):
        p = base_off + rela + 24 * k
        r_off, r_info = struct.unpack_from("<QQ", b, p)
        if words_va <= r_off < words_va + 32 and (r_info & M32) == 8:
            struct.pack_into("<Q", b, p + 8, (r_info & ~M32) | 37)
            n += 1
    bad = ni.load(bytes(b))
    check("E/a pointer table whose RELATIVE relocations are not applied: the read declines",
          n == 4 and declines(ni.call_jni, bad, P + "mixString", [("str", "abc")], "J"))
    # libc interposition: a preemptible definition named like a libc function is ambiguous -> poisoned GOT
    dynstr = img.dyn[5][0]
    soff = next(o - v for (v, m, fs, o, fl) in img.loads if v <= dynstr < v + fs) + dynstr
    b = bytearray(so)
    i = b.index(b"\x00kb2_round\x00", soff) + 1
    b[i:i + 9] = b"strlen\x00\x00\x00"
    inter = ni.load(bytes(b))
    check("E/a sibling whose exported name a system libc could interpose: the PLT slot declines",
          declines(ni.call_jni, inter, P + "mixString", [("str", "abc")], "J"))
    check("E/... while an unaffected function of the same image still runs",
          ni.call_jni(inter, P + "dispatch", [("I", 1), ("J", 7)], "J").value == m_dispatch(1, 7))
    # RELRO is read-only after relocation (bionic rounds it to whole pages)
    run = ni._Run(img, 0, 1000, 1000)
    rel = img.relro
    check("E/a write into RELRO is refused", rel is not None and declines(run.check_write, run.base + rel[0], 8))
    check("E/a non-ELF / 32-bit / foreign machine is refused at load",
          declines(ni.load, b"not an elf") and declines(ni.load, b"\x7fELF\x01\x01\x01" + b"\x00" * 60))


# ============================================================================== F. the Binary API
def _mini_exec():
    """A tiny ET_EXEC (non-PIE) x86-64 image: code at 0x401000 reads a table at 0x402000 absolutely."""
    code = bytes.fromhex("488b04fd00204000" "4801f0" "c3")   # mov rax,[rdi*8+0x402000]; add rax,rsi; ret
    table = struct.pack("<4Q", 11, 22, 33, 44)
    ph = []
    blob = bytearray(0x3000)
    blob[0x1000:0x1000 + len(code)] = code
    blob[0x2000:0x2000 + len(table)] = table
    ph.append(struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000, 0x401000, len(code), len(code), 0x1000))
    ph.append(struct.pack("<IIQQQQQQ", 1, 4, 0x2000, 0x402000, 0x402000, len(table), len(table), 0x1000))
    eh = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    eh += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, len(ph), 64, 0, 0)
    blob[0:64] = eh
    blob[64:64 + 56 * len(ph)] = b"".join(ph)
    return bytes(blob)


def test_binary_api():
    for abi in ("x86_64", "arm64"):
        so = fx("kb2_jni_%s.so" % abi)
        ok = all(ni.emulate_symbol(so, "kb2_round", [x, k]) == m_round(x, k)
                 for x, k in ((1, 0), (0xDEADBEEF, 5), (M64, 31)))
        check("F/%s emulate_symbol by exported name == model" % abi, ok)
        buf = bytearray(b"Hello, KB-2 decode!")
        want = bytes((c ^ (0x5A + 3 * i)) & 0xFF for i, c in enumerate(buf))
        s = ni.emulate_symbol(so, "kb2_decode", [buf, len(buf), 0x5A])
        check("F/%s bytearray argument decoded in place, int result" % abi,
              bytes(buf) == want and (s & M32) == sum(want))
        va = ni.load(so).symbol("kb2_round")
        check("F/%s emulate_symbol by vaddr" % abi, ni.emulate_symbol(so, va, [9, 3]) == m_round(9, 3))
        check("F/%s a static (.symtab) helper by name" % abi,
              ni.emulate_symbol(so, "kb2_fold", [b"abc", 3]) == m_fold(b"abc"))
        check("F/%s arch mismatch is refused" % abi,
              declines(ni.emulate_symbol, so, "kb2_round", [1, 1], arch="arm64" if abi == "x86_64" else "x86-64"))
    stripped = fx("kb2_jni_x86_64_stripped.so")
    check("F/a stripped image has no static helper", declines(ni.emulate_symbol, stripped, "kb2_fold", [b"a", 1]))
    check("F/a vaddr outside code is refused", declines(ni.emulate_symbol, stripped, 0x10, []))
    so15 = _saved_so("day-15/mobile-android-*/artifact/*.apk")
    if so15 is not None:
        s = ni.emulate_symbol(so15, "huntress_arena_secret", [], ret="cstr")
        img = ni.load(so15)
        va = img.symbol("huntress_arena_secret")
        code = img.file_bytes(va, 17)
        rel = struct.unpack("<i", code[code.index(b"\x48\x8d\x05") + 3:][:4])[0]
        lea_end = va + code.index(b"\x48\x8d\x05") + 7
        direct = img._cstr(lea_end + rel)
        check("F/day-15 a function returning a .rodata pointer, read as cstr == the bytes", s == direct and
              dcc.ANSWER.fullmatch(s) is not None)
        check("F/day-15 the same pointer as an int is address-dependent: declines",
              declines(ni.emulate_symbol, so15, "huntress_arena_secret", []))
    ex = _mini_exec()
    check("F/ET_EXEC: absolute addressing at its fixed vaddr", ni.emulate_symbol(ex, 0x401000, [2, 5]) == 38)
    check("F/ET_EXEC: an index past the table reads unmapped memory: declines",
          declines(ni.emulate_symbol, ex, 0x401000, [9, 5]))


# ============================================================================== G. dex-chain integration
STRING = "Ljava/lang/String;"
LONG = "Ljava/lang/Long;"
OBJ_ARR = "[Ljava/lang/Object;"
LAB = "Lcom/huntress/kb2/NativeLab;"
GATE = "Lcom/huntress/kb2/Gate;"
DEC = "Lcom/huntress/kb2/Decoy;"


class NDex:
    """A minimal classes.dex with FULL protos (return type + parameter list) and per-method access flags,
    so a native method is declared ACC_NATIVE exactly as d8 writes it."""

    def __init__(self):
        self.strings, self.types, self.protos, self.methods = [], [], [], []
        self.defs = {}
        self.supers = {}

    def extends(self, cls, sup):
        """Give a class this dex defines a superclass (class_def.superclass_idx; NO_INDEX otherwise)."""
        self.t(cls)
        self.t(sup)
        self.supers[cls] = sup

    def s(self, t):
        if t not in self.strings:
            self.strings.append(t)
        return self.strings.index(t)

    def t(self, d):
        self.s(d)
        if d not in self.types:
            self.types.append(d)
        return self.types.index(d)

    def proto(self, ret, params):
        shorty = "".join("L" if x[0] in "L[" else x for x in [ret] + list(params))
        key = (shorty, ret, tuple(params))
        self.s(shorty)
        self.t(ret)
        for x in params:
            self.t(x)
        if key not in self.protos:
            self.protos.append(key)
        return self.protos.index(key)

    def m(self, cls, name, ret, params):
        self.t(cls)
        self.s(name)
        key = (cls, name, self.proto(ret, params))
        if key not in self.methods:
            self.methods.append(key)
        return self.methods.index(key)

    def define(self, cls, midx, flags, units=None, regs=0, ins=0, outs=0, virtual=False):
        self.t(cls)
        self.defs.setdefault(cls, []).append((midx, flags, units, regs, ins, outs, virtual))

    @staticmethod
    def _uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | 0x80 if n else b)
            if not n:
                return bytes(out)

    def build(self):
        classes = list(self.defs)
        hdr = 112
        off = hdr + 4 * len(self.strings) + 4 * len(self.types) + 12 * len(self.protos) + 8 * len(self.methods) + \
            32 * len(classes)
        data = bytearray()

        def place(b, align=1):
            nonlocal off
            while (off + 0) % align:
                data.append(0)
                off += 1
            o = off
            data.extend(b)
            off += len(b)
            return o
        plists = []
        for (shorty, ret, params) in self.protos:
            if params:
                tl = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self.types.index(x)) for x in params)
                plists.append(place(tl, 4))
            else:
                plists.append(0)
        codes = {}
        for cls in classes:
            for (midx, flags, units, regs, ins, outs, virtual) in self.defs[cls]:
                if units is not None:
                    u = list(units) + ([0] if len(units) & 1 else [])
                    blk = struct.pack("<HHHHII", regs, ins, outs, 0, 0, len(units)) + struct.pack("<%dH" % len(u), *u)
                    codes[(cls, midx)] = place(blk, 4)
        cdata = []
        for cls in classes:
            direct = sorted([d for d in self.defs[cls] if not d[6]], key=lambda x: x[0])
            virt = sorted([d for d in self.defs[cls] if d[6]], key=lambda x: x[0])
            blk = bytearray(self._uleb(0) + self._uleb(0) + self._uleb(len(direct)) + self._uleb(len(virt)))
            for group in (direct, virt):
                prev = 0
                for (midx, flags, units, *_rest) in group:
                    blk += self._uleb(midx - prev) + self._uleb(flags) + self._uleb(codes.get((cls, midx), 0))
                    prev = midx
            cdata.append(place(bytes(blk)))
        sdata = [place(self._uleb(len(t)) + t.encode() + b"\x00") for t in self.strings]
        buf = bytearray(hdr) + bytearray(off - hdr - len(data)) + data
        buf[0:8] = b"dex\n035\x00"
        o = hdr
        struct.pack_into("<II", buf, 56, len(self.strings), o)
        for i, so in enumerate(sdata):
            struct.pack_into("<I", buf, o + 4 * i, so)
        o += 4 * len(self.strings)
        struct.pack_into("<II", buf, 64, len(self.types), o)
        for i, t in enumerate(self.types):
            struct.pack_into("<I", buf, o + 4 * i, self.strings.index(t))
        o += 4 * len(self.types)
        struct.pack_into("<II", buf, 72, len(self.protos), o)
        for i, (shorty, ret, params) in enumerate(self.protos):
            struct.pack_into("<III", buf, o + 12 * i, self.strings.index(shorty), self.types.index(ret), plists[i])
        o += 12 * len(self.protos)
        struct.pack_into("<II", buf, 88, len(self.methods), o)
        for i, (cls, name, pidx) in enumerate(self.methods):
            struct.pack_into("<HHI", buf, o + 8 * i, self.types.index(cls), pidx, self.strings.index(name))
        o += 8 * len(self.methods)
        struct.pack_into("<II", buf, 96, len(classes), o)
        for i, cls in enumerate(classes):
            sup = self.types.index(self.supers[cls]) if cls in self.supers else 0xFFFFFFFF
            struct.pack_into("<IIIIIIII", buf, o + 32 * i, self.types.index(cls), 0x11, sup, 0, 0xFFFFFFFF, 0,
                             cdata[i], 0)
        return bytes(buf)


def tail_format(a, d, vreg):
    """'ANS-%016X' of the long in vreg:vreg+1 via String.format(Long.valueOf), then return-object."""
    arr, box, fmt, out, idx = 10, 12, 13, 14, 9
    lv = d.m(LONG, "valueOf", LONG, ["J"])
    fm = d.m(STRING, "format", STRING, [STRING, OBJ_ARR])
    a.const4(idx, 1)
    a.new_array(arr, idx, d.t(OBJ_ARR))
    a.invoke(0x71, lv, [vreg, vreg + 1])
    a.move_result_object(box)
    a.const4(idx, 0)
    a.aput(0x4d, box, arr, idx)
    a.const_string(fmt, d.s("ANS-%016X"))
    a.invoke(0x71, fm, [fmt, arr])
    a.move_result_object(out)
    a.return_object(out)


def chain_dex(emit, natives, regs=24):
    """A dex with class C.run() (emit + tail) and the given native declarations [(cls, name, ret, params, flags,
    virtual)]; `emit(a, d, mids)` gets the native method indices by name."""
    d = NDex()
    a = Asm()
    mids = {}
    for (cls, name, ret, params, flags, virtual) in natives:
        mids[name] = d.m(cls, name, ret, params)
        d.define(cls, mids[name], flags, virtual=virtual)
    emit(a, d, mids)
    units = a.finish()
    run = d.m("Lcom/huntress/kb2/C;", "run", STRING, [])
    d.define("Lcom/huntress/kb2/C;", run, 0x9, units, regs, 0, 6)
    return d.build()


def apk(dex, libs):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", dex)
        for path, b in libs.items():
            zf.writestr(path, b)
        zf.writestr("assets/huntress_puzzle.json", json.dumps({"schema": "huntress.mobile.puzzle.v2",
                                                               "codec": "analysis"}))
    return buf.getvalue()


def members(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


Q = {"qid": "answer", "answer_format": {"kind": "pattern", "syntax": "ANS- followed by 16 uppercase hex"}}


def opts_of(ans):
    u = labels.parse(ans) if isinstance(ans, str) and labels.is_unsure(ans) else None
    return (u.key, [tuple(o) for o in u.options]) if u else None


def emit_mix_string(text):
    def emit(a, d, mids):
        a.const_string(2, d.s(text))
        a.invoke(0x71, mids["mixString"], [2])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    return emit


NAT_MIX = (LAB, "mixString", "J", [STRING], 0x109, False)


def test_dex_integration():
    x86, a64 = fx("kb2_jni_x86_64.so"), fx("kb2_jni_arm64.so")
    want = "ANS-%016X" % m_mix_string("hello native")
    for libs, tag in (({"lib/x86_64/libkb2.so": x86}, "x86_64"), ({"lib/arm64-v8a/libkb2.so": a64}, "arm64"),
                      ({"lib/x86_64/libkb2.so": x86, "lib/arm64-v8a/libkb2.so": a64}, "both ABIs agree")):
        files = members(apk(chain_dex(emit_mix_string("hello native"), [NAT_MIX]), libs))
        ans = dcc.answer(Q, files)
        o = opts_of(ans)
        check("G/%s: a String native the whole image proves -> unsure under the NEW key, the model's code" % tag,
              o == ("mobile.codec/analysis+native-image", [("analysis:dex-chain+native-image", want)]), repr(ans))
        check("G/%s: recover() never returns an image-only code plain" % tag, dcc.recover(files) is None)

    def emit_encode(a, d, mids):
        a.const_string(4, d.s("ANS-"))               # the literal that makes run() an entry of the chain
        a.const_string(2, d.s("chain-seed"))
        a.invoke(0x71, mids["encode"], [2])
        a.move_result_object(3)
        a.return_object(3)
    files = members(apk(chain_dex(emit_encode, [(LAB, "encode", STRING, [STRING], 0x109, False)]),
                        {"lib/x86_64/libkb2.so": x86}))
    o = opts_of(dcc.answer(Q, files))
    check("G/a native returning the code as a jstring (NewStringUTF) -> unsure, exact",
          o is not None and o[1] == [("analysis:dex-chain+native-image", m_encode("chain-seed"))])

    arr0 = [3, -7, 100, -128, 0, 55]

    def emit_bytes(a, d, mids):
        a.const4(4, 6)
        a.new_array(3, 4, d.t("[B"))
        for i, v in enumerate(arr0):
            a.const16(5, v)
            a.const4(6, i)
            a.aput(0x4f, 5, 3, 6)                    # aput-byte
        a.const16(7, 77)
        a.invoke(0x71, mids["mixBytes"], [3, 7])
        a.move_result_wide(0)
        a.const4(6, 2)
        a.aget(0x48, 5, 3, 6)                        # aget-byte arr[2] AFTER the native changed it
        a.unop(0x81, 6, 5)                           # int-to-long v6:v7 <- v5 (12x: registers below 16)
        a.binop(0xa2, 0, 0, 6)                       # xor-long v0, v0, v6
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_bytes, [(LAB, "mixBytes", "J", ["[B", "I"], 0x109, False)]),
                        {"lib/arm64-v8a/libkb2.so": a64}))
    h, new = m_mix_bytes(arr0, 77)
    want_b = "ANS-%016X" % ((h ^ (new[2] & M64)) & M64)
    o = opts_of(dcc.answer(Q, files))
    check("G/byte[] argument: the native's in-place commit is visible to the dex chain",
          o is not None and o[1] == [("analysis:dex-chain+native-image", want_b)], repr(o))

    def emit_make(a, d, mids):
        a.const16(2, 9)
        a.const_wide(3, 0xABCDEF)
        a.invoke(0x71, mids["makeBytes"], [2, 3, 4])
        a.move_result_object(6)
        a.const4(7, 4)
        a.aget(0x48, 8, 6, 7)                        # aget-byte r[4]
        a.unop(0x81, 0, 8)                           # int-to-long v0
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_make, [(LAB, "makeBytes", "[B", ["I", "J"], 0x109, False)]),
                        {"lib/x86_64/libkb2.so": x86}))
    o = opts_of(dcc.answer(Q, files))
    check("G/a returned byte[] (NewByteArray + SetByteArrayRegion) reads back exactly",
          o is not None and o[1] == [("analysis:dex-chain+native-image", "ANS-%016X" % (m_make_bytes(9, 0xABCDEF)[4] & M64))])

    def emit_twice(a, d, mids):
        a.const_string(2, d.s("twice"))
        a.invoke(0x71, mids["mixString"], [2])
        a.move_result_wide(0)
        a.invoke(0x71, mids["mixString"], [2])
        a.move_result_wide(16)
        a.binop(0xa2, 0, 0, 16)                      # equal results cancel: a stateful native would not
        a.const_wide(16, 0x1234567890ABCDEF)
        a.binop(0xa2, 0, 0, 16)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_twice, [NAT_MIX]), {"lib/x86_64/libkb2.so": x86}))
    o = opts_of(dcc.answer(Q, files))
    check("G/two calls of one native give the same value (no state between calls)",
          o is not None and o[1][0][1] == "ANS-1234567890ABCDEF")

    def emit_virtual(a, d, mids):
        a.new_instance(5, d.t(LAB))
        a.const_string(2, d.s("hello native"))
        a.invoke(0x6e, mids["mixString"], [5, 2])    # invoke-virtual: (JNIEnv*, jobject this, jstring)
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_virtual, [(LAB, "mixString", "J", [STRING], 0x101, True)]),
                        {"lib/x86_64/libkb2.so": x86}))
    o = opts_of(dcc.answer(Q, files))
    check("G/an instance native (invoke-virtual) gets `this` and the right arguments",
          o is not None and o[1] == [("analysis:dex-chain+native-image", want)])

    # --- declines
    a64_bad = bytearray(a64)
    img = ni.load(a64)
    sbox_at = None
    for s in img.symtab:
        if s.name == "SBOX":
            sbox_at = next(o - v for (v, m, fs, o, fl) in img.loads if v <= s.value < v + fs) + s.value
    a64_bad[sbox_at] ^= 0x40
    files = members(apk(chain_dex(emit_mix_string("hello native"), [NAT_MIX]),
                        {"lib/x86_64/libkb2.so": x86, "lib/arm64-v8a/libkb2.so": bytes(a64_bad)}))
    check("G/two ABIs that disagree on the native -> no code at all", dcc.answer(Q, files) is None)
    fake32 = b"\x7fELF\x01\x01\x01" + b"\x00" * 57 + b"\x00" + (P + "mixString").encode() + b"\x00"
    files = members(apk(chain_dex(emit_mix_string("hello native"), [NAT_MIX]),
                        {"lib/x86_64/libkb2.so": x86, "lib/armeabi-v7a/libkb2.so": fake32}))
    o = opts_of(dcc.answer(Q, files))
    # r3 (review of e71b954): demoted, not dropped: which ABI a device loads decides the answer, so the reading is
    # an unsure pick under a key of its own (it was None on the first build; the shipped tree answered plain)
    check("G/a library this engine cannot emulate also exports the symbol -> unsure under +abi-unverified",
          o == ("mobile.codec/analysis+native-image+abi-unverified",
                [("analysis:dex-chain+native-image+abi-unverified", want)]) and dcc.recover(files) is None, repr(o))
    files = members(apk(chain_dex(emit_mix_string("hello native"), [(LAB, "mixString", "J", [STRING], 0x9, False)]),
                        {"lib/x86_64/libkb2.so": x86}))
    before = PASS
    check("G/a method NOT declared native never binds to the library", dcc.answer(Q, files) is None)
    del before

    def emit_gate(fn, ln):
        def emit(a, d, mids):
            a.const_string(4, d.s("ANS-"))           # the literal that makes run() an entry of the chain
            a.const32(2, ln)
            a.invoke(0x71, mids[fn], [2])
            a.move_result_object(3)
            a.return_object(3)
        return emit
    gate = fx("kb2_gate_x86_64.so")
    files = members(apk(chain_dex(emit_gate("nativeEvidence", 5), [(GATE, "nativeEvidence", STRING, ["I"], 0x109, False)]),
                        {"lib/x86_64/libgate.so": gate}))
    check("G/the NULL (gate-FAIL) sentinel declines -> no code", dcc.answer(Q, files) is None)
    files = members(apk(chain_dex(emit_gate("nativeEvidence", 0x197DE),
                                  [(GATE, "nativeEvidence", STRING, ["I"], 0x109, False)]),
                        {"lib/x86_64/libgate.so": gate}))
    o = opts_of(dcc.answer(Q, files))
    check("G/the C-pointer jstring shortcut -> unsure under its own +native-cstr key",
          o == ("mobile.codec/analysis+native-cstr", [("analysis:dex-chain+native-cstr", "ANS-0F899F2B0D6E5B4B")]),
          repr(o))

    def emit_spin(a, d, mids):
        a.const_wide(0, 5)
        a.invoke(0x71, mids["spin"], [0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_spin, [(DEC, "spin", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libdecoy.so": fx("kb2_decoy_x86_64.so")}))
    t = time.perf_counter()
    res = dcc.answer(Q, files)
    dt = time.perf_counter() - t
    # (most of that time is the shipped readers' own step budgets, unchanged by this build)
    check("G/a spinning native declines (whole chain %.0f ms)" % (1000 * dt), res is None)
    usage = {}
    t = time.perf_counter()
    dec = declines(ni.call_jni, fx("kb2_decoy_x86_64.so"), D + "spin", [("J", 5)], "J",
                   max_blocks=nib.PER_RUN_BLOCKS, max_mem=nib.PER_RUN_MEM, usage=usage)
    dt = time.perf_counter() - t
    check("G/... the whole-image part declines by its WORK budget (%d blocks, %.0f ms)" % (usage.get("blocks", 0),
                                                                                       1000 * dt),
          dec and usage.get("blocks", 0) <= 2 * nib.PER_RUN_BLOCKS + 2 and dt < 1.0)


def test_legacy_unchanged():
    """A native the shipped readers already prove: the whole image cross-checks it and the answer is the
    judged one, plain, exactly as before (real ledger)."""
    so = _saved_so("day-25/mobile-android-*/mastery/artifact/delivery-06/*.apk")
    if so is None:
        print("SKIP G/legacy (Day-25 APK absent)")
        return
    img = ni.load(so)
    sym = next(s for s in img.exports() if s.endswith("JNIBoundary_nativeShare"))
    cls = "L" + sym[len("Java_"):].rsplit("_", 1)[0].replace("_", "/") + ";"
    code = dcc._parse_so(so)[sym][1]
    gate = struct.unpack("<I", code[code.index(b"\x81\xfe") + 2:][:4])[0]
    ln = 0x10000 | gate
    seed = 0x0123456789ABCDEF

    def emit(a, d, mids):
        a.const_wide(0, seed)
        a.const32(2, ln)
        a.invoke(0x71, mids["nativeShare"], [0, 1, 2])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit, [(cls, "nativeShare", "J", ["J", "I"], 0x109, False)]),
                        {"lib/x86_64/libarena.so": so}))
    hand = dcc._emulate_x86(code, [0, 0, seed, ln]) & M64
    calls = {"n": 0}
    orig = nib._run

    def counting(*a, **k):
        calls["n"] += 1
        return orig(*a, **k)
    nib._run = counting
    try:
        ans = dcc.answer(Q, files)
    finally:
        nib._run = orig
    want = "ANS-%016X" % hand
    plain_ok = (ans == want) if labels.pick("mobile.codec/analysis", [("analysis:dex-chain", want)]) == want else \
        (opts_of(ans) == ("mobile.codec/analysis", [("analysis:dex-chain", want)]))
    check("G/a legacy-proven native: cross-checked by the whole image, answered under the judged key as before",
          plain_ok and calls["n"] >= 1, "%r calls=%d" % (ans, calls["n"]))


def test_codec_search_end_to_end():
    try:
        import day21_mobile_specimens as S
        C, lab = S._load(str(ROOT / "solvers"), "real")
    except Exception as e:
        print("SKIP G/end-to-end (%s)" % e)
        return
    x86 = fx("kb2_jni_x86_64.so")
    blob = apk(chain_dex(emit_mix_string("hello native"), [NAT_MIX]), {"lib/x86_64/libkb2.so": x86})
    ans, secs, _last = S.solve_with(C, blob, 1)
    o = opts_of(ans)
    check("G/end to end through codec_search.solve_set: unsure under the new key, never plain (%.0f ms)" % (1000 * secs),
          o is not None and o[0] == "mobile.codec/analysis+native-image" and not (isinstance(ans, str) and
                                                                                 not lab.is_unsure(ans)), repr(ans))


# ============================================================================== I. load-time code (r2)
LOAD = "Lcom/huntress/kb2/Load;"
LCLS = "com/huntress/kb2/Load"
LNAT = {(LCLS, "regMix", "(J)J"), (LCLS, "regCode", "()Ljava/lang/String;"), (LCLS, "ctorValue", "(J)J"),
        (LCLS, "ctorCode", "()Ljava/lang/String;")}
L = "Java_com_huntress_kb2_Load_"
LOAD_CODE = "ANS-6A1F3C9E0B7D2485"        # tests/native_image_fixtures.py KB2_LOAD_CODE (stored XOR 0x5A in .data)


def m_load_table(seed=0x1234):
    """The .bss table the constructor builds from the seed DT_INIT set (0x9999 if DT_INIT had not run first)."""
    out, x = [], seed
    for _ in range(8):
        x = (x * 6364136223846793005 + 1442695040888963407) & M64
        out.append(x)
    return out


def m_ctor_value(x, seed=0x1234):
    h = 0xCBF29CE484222325
    for c in LOAD_CODE.encode()[:16]:
        h = ((h ^ c) * 0x100000001B3) & M64
    return h ^ m_load_table(seed)[x & 7]


def m_reg_mix(x):
    return ((x * 0x9E3779B97F4A7C15) & M64) ^ m_load_table()[1]


def test_load_phase_engine():
    for abi in ("x86_64", "arm64"):
        so = fx("kb2_load_%s.so" % abi)
        img = ni.load(so)
        info = ni.load_info(img, {LCLS}, LNAT)
        reg = info["registered"]
        check("I/%s load_info: JNI_OnLoad (GetEnv, FindClass, RegisterNatives, DeleteLocalRef) registers regMix "
              "and regCode, version 1.6" % abi,
              info["version"] == 0x10006 and set(reg) == {(LCLS, "regMix", "(J)J"),
                                                         (LCLS, "regCode", "()Ljava/lang/String;")}
              and all(img._in_exec(v) for v in reg.values()), repr(info))
        check("I/%s ctorValue == model: DT_INIT before DT_INIT_ARRAY, .data decrypted, .bss table built" % abi,
              all(ni.call_jni(img, L + "ctorValue", [("J", x)], "J", classes={LCLS}, natives=LNAT).value ==
                  m_ctor_value(x) for x in (0, 3, 7, -1)))
        r = ni.call_jni(img, L + "ctorCode", [], "str", classes={LCLS}, natives=LNAT)
        check("I/%s ctorCode: NewStringUTF of the constructor-decrypted .data == the code" % abi,
              r.kind == "str" and r.value == LOAD_CODE)
        va = reg[(LCLS, "regMix", "(J)J")]
        got = ni.call_jni(img, None, [("J", 5)], "J", classes={LCLS}, natives=LNAT, entry=va).value
        dl = ni.call_jni(img, L + "regMix", [("J", 5)], "J", classes={LCLS}, natives=LNAT).value
        check("I/%s the REGISTERED regMix == model, and differs from the decoy export a dlsym would bind" % abi,
              got == m_reg_mix(5) and dl == 6 and got != dl)
        r = ni.call_jni(img, None, [], "str", classes={LCLS}, natives=LNAT,
                        entry=reg[(LCLS, "regCode", "()Ljava/lang/String;")])
        check("I/%s the registered regCode == the code" % abi, r.kind == "str" and r.value == LOAD_CODE)
        check("I/%s without the dex's classes the load phase declines (FindClass is never assumed)" % abi,
              declines(ni.call_jni, img, L + "ctorValue", [("J", 3)], "J") and declines(ni.load_info, img))
        check("I/%s emulate_symbol runs the constructors (init=auto); init=skip reads the pristine image" % abi,
              ni.emulate_symbol(so, L + "ctorValue", [0, 0, 3]) == m_ctor_value(3) and
              ni.emulate_symbol(so, L + "ctorValue", [0, 0, 3], init="skip") != m_ctor_value(3))
        a = [ni.call_jni(img, L + "ctorValue", [("J", 2)], "J", classes={LCLS}, natives=LNAT).value for _ in range(2)]
        check("I/%s repeated calls after the load phase agree (the snapshot is the loaded state)" % abi,
              a[0] == a[1] == m_ctor_value(2))
        check("I/%s a native reading its uninitialised stack after the load phase declines (never the "
              "constructor's leftover pattern)" % abi,
              declines(ni.call_jni, img, L + "stackLeft", [("J", 5)], "J", classes={LCLS}, natives=LNAT))
    for abi in ("x86_64", "arm64"):
        img = ni.load(fx("kb2_load_ctoronly_%s.so" % abi))
        info = ni.load_info(img, (), ())
        check("I/%s constructors only: load_info registers nothing, no version" % abi,
              info == {"load_code": True, "version": None, "registered": {}})
        check("I/%s constructors only: ctorValue == model with no class list at all" % abi,
              ni.call_jni(img, L + "ctorValue", [("J", 5)], "J").value == m_ctor_value(5))
    check("I/an image with no load-time code answers load_info at once",
          ni.load_info(ni.load(fx("kb2_jni_x86_64.so"))) == {"load_code": False, "version": None, "registered": {}})
    for name, why in (("badctor", "a constructor calling an unmodelled import (getpid)"),
                      ("ghost", "a RegisterNatives of a method the dex does not declare"),
                      ("badver", "a JNI_OnLoad returning a version ART refuses"),
                      ("noclass", "a FindClass of a class the dex does not define")):
        img = ni.load(fx("kb2_load_%s_x86_64.so" % name))
        dec = declines(ni.load_info, img, {LCLS}, LNAT) and all(
            declines(ni.call_jni, img, L + s, ja, rt, classes={LCLS}, natives=LNAT)
            for s, ja, rt in (("ctorValue", [("J", 3)], "J"), ("ctorCode", [], "str"), ("regMix", [("J", 5)], "J")))
        check("I/%s: the load phase and every call decline" % why, dec)


NAT_LOAD = [(LOAD, "regMix", "J", ["J"], 0x109, False), (LOAD, "regCode", STRING, [], 0x109, False),
            (LOAD, "ctorValue", "J", ["J"], 0x109, False), (LOAD, "ctorCode", STRING, [], 0x109, False)]


def _emit_long(fn, arg):
    def emit(a, d, mids):
        a.const_wide(0, arg)
        a.invoke(0x71, mids[fn], [0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    return emit


def _emit_str(fn):
    def emit(a, d, mids):
        a.const_string(4, d.s("ANS-"))               # the literal that makes run() an entry of the chain
        a.invoke(0x71, mids[fn], [])
        a.move_result_object(3)
        a.return_object(3)
    return emit


def test_load_phase_dex():
    good = {"lib/x86_64/libload.so": fx("kb2_load_x86_64.so")}
    both = {"lib/x86_64/libload.so": fx("kb2_load_x86_64.so"), "lib/arm64-v8a/libload.so": fx("kb2_load_arm64.so")}
    decoy = "ANS-%016X" % 6
    want = "ANS-%016X" % m_reg_mix(5)
    for libs, tag in ((good, "x86_64"), (both, "x86_64 + arm64 (each registers; they agree)")):
        files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD), libs))
        o = opts_of(dcc.answer(Q, files))
        # the KB-2 port onto so-ambig: a library of the delivery has a JNI_OnLoad that is not provably inert, or
        # DT_INIT / DT_INIT_ARRAY (so-ambig's rule 1), beside an export the loose rule matches: so-ambig declines every
        # binding of it, and the merged path declines with it (a RegisterNatives binding included), where the bridge
        # alone read it (unsure, or plain); a registered native that NO symbol matches still reads (image only, unsure)
        check("I/%s: a RegisterNatives-bound native beside the decoy export -> no code (so-ambig: a JNI_OnLoad not "
              "proven inert; the bridge alone read the REGISTERED function's code, unsure)" % tag + PORT,
              dcc.answer(Q, files) is None, repr(o))
    files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD), good))
    saved = dcc.native_image_bridge
    dcc.native_image_bridge = None
    try:
        legacy_alone = dcc.answer(Q, files)
    finally:
        dcc.native_image_bridge = saved
    legacy_code = legacy_alone if not labels.is_unsure(legacy_alone or "") else (opts_of(legacy_alone) or (0, [[0, 0]]))[1][0][1]
    # the KB-2 port onto so-ambig: the shipped readers alone now apply so-ambig's binding rules (a JNI_OnLoad that is
    # not provably inert declines every binding), so they no longer read the decoy export either
    check("I/(the hole closed) the shipped readers alone no longer answer the decoy EXPORT %s plain (so-ambig's rules "
          "since the port; before them they did)" % decoy + PORT, not plain_is(legacy_alone, decoy) and
          legacy_code != decoy, repr(legacy_alone))
    ans = dcc.answer(Q, files)
    check("I/... with the bridge the decoy code is never answered, plain or offered",
          decoy not in json.dumps(ans) and dcc.recover(files) is None)
    files = members(apk(chain_dex(_emit_str("regCode"), NAT_LOAD), good))
    o = opts_of(dcc.answer(Q, files))
    check("I/a registered String native returns the constructor-decrypted code (unsure, new key)",
          o == ("mobile.codec/analysis+native-image", [("analysis:dex-chain+native-image", LOAD_CODE)]), repr(o))
    for abi in ("x86_64", "arm64"):
        libs = {"lib/%s/libctor.so" % abi: fx("kb2_load_ctoronly_%s.so" % abi)}
        files = members(apk(chain_dex(_emit_long("ctorValue", 3), NAT_LOAD), libs))
        o = opts_of(dcc.answer(Q, files))
        check("I/%s constructors only: an exported native reading constructor state -> no code (so-ambig's "
              "constructor rule; the bridge alone read the model's code, unsure)" % abi + PORT,
              dcc.answer(Q, files) is None, repr(o))
    for name, why in (("badctor", "import-getpid"), ("ghost", "registernatives"), ("badver", "version"),
                      ("noclass", "findclass")):
        libs = {"lib/x86_64/libbad.so": fx("kb2_load_%s_x86_64.so" % name)}
        files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD), libs))
        res = dcc.answer(Q, files)
        files2 = members(apk(chain_dex(_emit_long("ctorValue", 3), NAT_LOAD), libs))
        # fix round 1 (review of e281f95, items 1b and 7): an unmodelled JNI_OnLoad no longer declines the delivery
        # (6aa5104 answered such deliveries; a decline opened codec_search's decoy fall-through): the export's
        # legacy reading stays, never plain, under a key that names why the load phase was not read
        k = "mobile.codec/analysis+onload-unverified@" + why
        check("I/%s: an unmodelled load phase -> no code (so-ambig: a JNI_OnLoad not proven inert; the bridge alone "
              "gave the export's legacy reading as an unsure pick under %s); a native the legacy reader cannot read "
              "(constructor state) -> no code" % (name, k) + PORT,
              res is None and dcc.recover(files) is None and dcc.answer(Q, files2) is None, repr(res))
    other = "Lcom/huntress/kb2/Other;"
    # Other.regMix (declared last, so the chain calls it): nothing registers or exports it, while the shipped
    # readers' loose suffix match would bind the Load decoy export Java_..._Load_regMix to it
    files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD + [(other, "regMix", "J", ["J"], 0x109, False)]),
                        good))
    saved = dcc.native_image_bridge
    dcc.native_image_bridge = None
    try:
        loose = dcc.answer(Q, files)
    finally:
        dcc.native_image_bridge = saved
    check("I/a native nothing registers or exports beside a JNI_OnLoad -> no code (the shipped readers' loose "
          "suffix match gave %s)" % (opts_of(loose) or loose,), dcc.answer(Q, files) is None)
    mixed = {"lib/x86_64/libload.so": fx("kb2_load_x86_64.so"), "lib/arm64-v8a/libload.so": fx("kb2_load_ghost_x86_64.so")}
    files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD), mixed))
    check("I/one library's JNI_OnLoad cannot be modelled -> no binding of the dex is known: no code",
          dcc.answer(Q, files) is None)


# ============================================================================== J. machine-dependent instructions (r2)
E = "Java_com_huntress_kb2_Env_"


def test_environment():
    for abi in ("x86_64", "arm64"):
        img = ni.load(fx("kb2_env_%s.so" % abi))
        for name, what in (("timing", "a timing check (rdtsc / cntvct_el0)"),
                           ("cpuflag", "a CPU identity check (cpuid hypervisor bit / midr_el1)"),
                           ("random", "a hardware random number (rdrand / RNDR)"),
                           ("xcr", "a machine-state read (xgetbv / ctr_el0)")):
            check("J/%s %s declines" % (abi, what), declines(ni.call_jni, img, E + name, [("J", 7)], "J"))
        check("J/%s ... while a plain function of the same image answers" % abi,
              ni.call_jni(img, E + "plain", [("J", 7)], "J").value == 22)
        r = ni.call_jni(img, E + "jniMisc", [("str", "abc")], "I")
        check("J/%s GetVersion 1.6, ExceptionOccurred NULL, ExceptionClear, DeleteLocalRef: exact" % abi,
              r.value == 0x10006 + 1000 + 3, repr(r.value))
        check("J/%s a reference used after DeleteLocalRef declines" % abi,
              declines(ni.call_jni, img, E + "useAfterDelete", [("str", "abc")], "I"))
        # the shipped single-function engine (the legacy path's general reader) is vetted the same way
        syms = dcc._parse_so(fx("kb2_env_%s.so" % abi))
        run1 = ne.emulate_x86_sysv if abi == "x86_64" else ne.emulate_arm64_aapcs
        dec1 = []
        for name in ("timing", "cpuflag", "random", "xcr"):
            try:
                run1(syms[E + name][1], [0, 0, 7])
                dec1.append(False)
            except ne.EmulationError:
                dec1.append(True)
        check("J/%s native_emulate (single function) declines the same four checks" % abi, all(dec1), repr(dec1))
        check("J/%s ... and still answers the plain function" % abi, run1(syms[E + "plain"][1], [0, 0, 7]) == 22)
        env_nat = [("Lcom/huntress/kb2/Env;", n, "J", ["J"], 0x109, False) for n in ("timing", "cpuflag", "plain")]
        libs = {"lib/%s/libenv.so" % ("x86_64" if abi == "x86_64" else "arm64-v8a"): fx("kb2_env_%s.so" % abi)}
        none = all(dcc.answer(Q, members(apk(chain_dex(_emit_long(n, 7), env_nat), libs))) is None
                   for n in ("timing", "cpuflag"))
        check("J/%s through the dex chain: an emulator check gives no code at all (legacy and whole image)" % abi, none)
        ans = dcc.answer(Q, members(apk(chain_dex(_emit_long("plain", 7), env_nat), libs)))
        o = opts_of(ans)
        check("J/%s ... while the plain native's code is the judged key's reading, as before" % abi,
              ans == "ANS-%016X" % 22 or (o is not None and o[0] == "mobile.codec/analysis"
                                          and o[1] == [("analysis:dex-chain", "ANS-%016X" % 22)]), repr(ans))
    # an image with a writable AND executable segment: bionic refuses it (API 26+), so does the engine
    so = bytearray(fx("kb2_jni_x86_64.so"))
    phoff = struct.unpack_from("<Q", so, 0x20)[0]
    for i in range(struct.unpack_from("<H", so, 0x38)[0]):
        o = phoff + 56 * i
        if struct.unpack_from("<I", so, o)[0] == 1 and struct.unpack_from("<I", so, o + 4)[0] == 5:
            struct.pack_into("<I", so, o + 4, 7)
            break
    check("J/a PT_LOAD both writable and executable is refused at load", declines(ni.load, bytes(so)))


# ============================================================================== K. bounds of the bridge (r2)
def test_bridge_bounds():
    so = fx("kb2_jni_x86_64.so")
    check("K/native_emulate.emulate_symbol re-exports the whole-image entry for a fields_dNN.py author",
          ne.emulate_symbol(so, "kb2_round", [0xDEADBEEF, 5]) == ni.emulate_symbol(so, "kb2_round", [0xDEADBEEF, 5])
          == m_round(0xDEADBEEF, 5))
    saved = nib.MAX_IMAGE_BYTES
    nib.MAX_IMAGE_BYTES = 1000                     # every fixture is "too large" now
    try:
        files = members(apk(chain_dex(emit_mix_string("hello native"), [NAT_MIX]), {"lib/x86_64/libkb2.so": so}))
        check("K/a library past the size bounds is not emulated: an image-only code is not produced",
              dcc.answer(Q, files) is None)
        good = {"lib/x86_64/libload.so": fx("kb2_load_x86_64.so")}
        files = members(apk(chain_dex(_emit_long("regMix", 5), NAT_LOAD), good))
        o = opts_of(dcc.answer(Q, files))
        check("K/... and its JNI_OnLoad counts as one that cannot be modelled: no code (so-ambig: a JNI_OnLoad not "
              "proven inert; the bridge alone gave the export unsure under +onload-unverified@size)" + PORT,
              dcc.answer(Q, files) is None, repr(o))
        env_nat = [("Lcom/huntress/kb2/Env;", "plain", "J", ["J"], 0x109, False)]
        files = members(apk(chain_dex(_emit_long("plain", 7), env_nat), {"lib/x86_64/libenv.so": fx("kb2_env_x86_64.so")}))
        ans = dcc.answer(Q, files)
        o = opts_of(ans)
        # KB-2 fix round 2 (the review of 4250749, item b): the whole image was needed for its cross-check and was not
        # asked, so the legacy reading is demoted (it stood plain under the judged key, and an emulator check in such
        # a library took its emulator leg plain)
        check("K/... while a legacy-proven native of such a library keeps the legacy reading, demoted "
              "+image-unchecked@plain (fix round 2, item b; never plain unchecked)",
              o == ("mobile.codec/analysis+image-unchecked@plain",
                    [("analysis:dex-chain+image-unchecked@plain", "ANS-%016X" % 22)]), repr(ans))
    finally:
        nib.MAX_IMAGE_BYTES = saved


# ============================================================================== L. the fixer round (r3)
def r3(name, abi="x86_64"):
    return fx("kb2_r3_%s_%s.so" % (name, abi))


IMG_KEY = ("mobile.codec/analysis+native-image", "analysis:dex-chain+native-image")


def judged_or_unsure(ans, want, key="mobile.codec/analysis", route="analysis:dex-chain"):
    """What a legacy-proven native gets under the judged key: plain once the ledger accepted the route, else an
    unsure pick of exactly that code under exactly that key."""
    if labels.pick(key, [(route, want)]) == want:
        return ans == want
    return opts_of(ans) == (key, [(route, want)])


def legacy_alone(files):
    """The answer with the bridge switched off: the shipped readers alone (the tree before KB-2)."""
    saved = dcc.native_image_bridge
    dcc.native_image_bridge = None
    try:
        return dcc.answer(Q, files)
    finally:
        dcc.native_image_bridge = saved


def plain_is(ans, code):
    """True when `ans` is `code` answered PLAIN (the wrong plain the counterfactual 'hole' checks look for)."""
    return isinstance(ans, str) and not labels.is_unsure(ans) and ans == code


PORT = " [KB-2 port onto so-ambig: more restrictive]"


def unsure_or_none(ans, code=None):
    """True when `ans` is None, or unsure (offering `code` first when one is given): never plain."""
    if ans is None:
        return True
    o = opts_of(ans)
    return o is not None and (code is None or (o[1] and o[1][0][1] == code))


def code_of(ans):
    if ans is None or not isinstance(ans, str):
        return None
    if labels.is_unsure(ans):
        o = opts_of(ans)
        return o[1][0][1] if o and o[1] else None
    return ans


def emit_loop(fn, n, arg=1, chained=True):
    """C.run(): call the static native `fn` n times, each call fed the last result (chained) or the same argument."""
    def emit(a, d, mids):
        a.const_wide(0, arg)
        a.const32(8, n)
        a.const4(9, 0)
        a.label("top")
        a.if_test(0x35, 9, 8, "done")                # if-ge v9, v8
        a.invoke(0x71, mids[fn], [0, 1])
        a.move_result_wide(0 if chained else 2)
        a.u.append(0xd8 | (9 << 8))                  # add-int/lit8 v9, v9, #1
        a.u.append(9 | (1 << 8))
        a.goto16("top")
        a.label("done")
        tail_format(a, d, 0 if chained else 2)
    return emit


class _CountCalls:
    """Counts native_image.call_jni calls made through the bridge while active (the bridge's process caches are
    emptied first, so an evaluation an earlier check computed is computed, and counted, again)."""

    def __enter__(self):
        self.n = 0
        nib.clear_caches()
        self.orig = nib._ni.call_jni

        def counting(*a, **k):
            self.n += 1
            return self.orig(*a, **k)
        nib._ni.call_jni = counting
        return self

    def __exit__(self, *exc):
        nib._ni.call_jni = self.orig
        return False


def test_r3_binding():
    """Review of e71b954, items 1 and 2 (wrong plain answers through the binding), and the rule that every library
    binding a symbol must agree."""
    decoy, want = "ANS-%016X" % 6, "ANS-%016X" % m_reg_mix(5)
    loadso = fx("kb2_load_x86_64.so")
    # (1a) multidex: classes.dex calls Load.regMix, which classes2.dex declares native and JNI_OnLoad registers
    d1, a1 = NDex(), Asm()
    mid = d1.m(LOAD, "regMix", "J", ["J"])
    a1.const_wide(0, 5)
    a1.invoke(0x71, mid, [0, 1])
    a1.move_result_wide(0)
    tail_format(a1, d1, 0)
    units = a1.finish()
    run = d1.m("Lcom/huntress/kb2/C;", "run", STRING, [])
    d1.define("Lcom/huntress/kb2/C;", run, 0x9, units, 24, 0, 6)
    d2 = NDex()
    for (cls, name, ret, params, flags, virtual) in NAT_LOAD:
        d2.define(cls, d2.m(cls, name, ret, params), flags, virtual=virtual)
    files = members(apk(d1.build(), {"lib/x86_64/libload.so": loadso}))
    files["classes2.dex"] = d2.build()
    o = opts_of(dcc.answer(Q, files))
    check("L/multidex: a native classes2.dex declares and JNI_OnLoad registers, called from classes.dex -> no code "
          "(so-ambig: a JNI_OnLoad not proven inert beside the decoy export; the bridge alone read the REGISTERED "
          "function's code, unsure; review: the decoy export, PLAIN)" + PORT, dcc.answer(Q, files) is None, repr(o))
    check("L/... (the hole) the shipped readers alone never answer the decoy export plain (so-ambig's rules since "
          "the port)" + PORT, not plain_is(legacy_alone(files), decoy), repr(legacy_alone(files)))
    # (1b) a subclass reference: invoke-static Sub.regMix, Sub extends Load (ART resolves it to Load.regMix)
    sub = "Lcom/huntress/kb2/Sub;"
    d = NDex()
    for (cls, name, ret, params, flags, virtual) in NAT_LOAD:
        d.define(cls, d.m(cls, name, ret, params), flags, virtual=virtual)
    d.extends(sub, LOAD)
    a = Asm()
    a.const_wide(0, 5)
    a.invoke(0x71, d.m(sub, "regMix", "J", ["J"]), [0, 1])
    a.move_result_wide(0)
    tail_format(a, d, 0)
    units = a.finish()
    run = d.m("Lcom/huntress/kb2/C;", "run", STRING, [])
    d.define("Lcom/huntress/kb2/C;", run, 0x9, units, 24, 0, 6)
    d.define(sub, d.m(sub, "<init>", "V", []), 0x10001)
    files = members(apk(d.build(), {"lib/x86_64/libload.so": loadso}))
    o = opts_of(dcc.answer(Q, files))
    check("L/a subclass reference to a registered static native -> no code (so-ambig: a JNI_OnLoad not proven inert "
          "beside the decoy export; the bridge alone read the REGISTERED function's code, unsure; review: the decoy "
          "export, PLAIN)" + PORT, dcc.answer(Q, files) is None, repr(o))
    check("L/... (the hole) the shipped readers alone never answer the decoy export plain (so-ambig's rules since "
          "the port)" + PORT, not plain_is(legacy_alone(files), decoy), repr(legacy_alone(files)))
    # (2) the shipped reader's loose suffix match: Aaa_mix (a decoy it reads first) beside the exact NativeLab_mix
    loose = r3("loose")
    files = members(apk(chain_dex(_emit_long("mix", 5), [(LAB, "mix", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libadv.so": loose}))
    check("L/loose: the exact export calls an unmodelled import -> no code (review: the decoy Aaa_mix, PLAIN)",
          dcc.answer(Q, files) is None)
    check("L/... (the hole) the shipped readers alone never answer Aaa_mix plain (so-ambig binds the exact name)" + PORT,
          not plain_is(legacy_alone(files), "ANS-%016X" % 0x1243), repr(legacy_alone(files)))
    files = members(apk(chain_dex(_emit_long("twin", 5), [(LAB, "twin", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libadv.so": loose}))
    check("L/one library exporting Aaa_twin and NativeLab_twin: the legacy reader reads the EXACT symbol -> its code "
          "under the judged key", judged_or_unsure(dcc.answer(Q, files), "ANS-%016X" % 40), repr(dcc.answer(Q, files)))
    check("L/... (the hole) the shipped readers alone never answer Aaa_twin plain (so-ambig binds the exact name)" + PORT,
          not plain_is(legacy_alone(files), "ANS-%016X" % 0x1243), repr(legacy_alone(files)))
    # one library defining one JNI name twice (two addresses): which a lookup finds depends on the hash chain
    img = ni.load(loose)
    symtab = img.dyn[6][0]
    off = next(o - v for (v, m, fs, o, fl) in img.loads if v <= symtab < v + fs) + symtab
    names = [s.name for s in img.dynsyms]
    ia, ib = names.index("Java_com_huntress_kb2_Aaa_twin"), names.index(P + "twin")
    twice = bytearray(loose)
    twice[off + 24 * ia:off + 24 * ia + 4] = twice[off + 24 * ib:off + 24 * ib + 4]
    files = members(apk(chain_dex(_emit_long("twin", 5), [(LAB, "twin", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libadv.so": bytes(twice)}))
    check("L/one library defines NativeLab_twin twice (two addresses) -> no code",
          P + "twin" in ni.load(bytes(twice)).ambiguous_exports() and dcc.answer(Q, files) is None)
    # a static .symtab entry that gives the exact JNI name a decoy's address: the shipped reader's table (it merges
    # .dynsym and .symtab by name) then holds the decoy's bytes for it; dlsym returns the .dynsym export
    symt = bytearray(loose)
    shoff, shnum = struct.unpack_from("<Q", symt, 0x28)[0], struct.unpack_from("<H", symt, 0x3C)[0]
    secs = [struct.unpack_from("<IIQQQQIIQQ", symt, shoff + 64 * i) for i in range(shnum)]
    patched = False
    for (_n, typ, _f, _a, off, size, link, _i, _al, ent) in secs:
        if typ != 2 or ent != 24:
            continue
        stro = secs[link][4]
        entries = {}
        for k in range(size // 24):
            st_name = struct.unpack_from("<I", symt, off + 24 * k)[0]
            end = symt.index(b"\x00", stro + st_name)
            entries[bytes(symt[stro + st_name:end]).decode("latin1")] = off + 24 * k
        a_ent, b_ent = entries.get("Java_com_huntress_kb2_Aaa_twin"), entries.get(P + "twin")
        if a_ent and b_ent:
            symt[b_ent + 8:b_ent + 24] = symt[a_ent + 8:a_ent + 24]     # st_value and st_size of the decoy
            patched = True
    files = members(apk(chain_dex(_emit_long("twin", 5), [(LAB, "twin", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libadv.so": bytes(symt)}))
    saved = nib.MAX_IMAGE_CALLS
    nib.MAX_IMAGE_CALLS = 0                        # the whole image not asked: the legacy reading would stand alone
    try:
        alone = dcc.answer(Q, files)
    finally:
        nib.MAX_IMAGE_CALLS = saved
    # since the port: so-ambig's rule 2 (an export of the name whose code is not the table's) declines the binding, so
    # with the whole image too there is no code (the image's own reading, unsure before, is not taken)
    check("L/a .symtab entry giving the exact JNI name a decoy's bytes: never read as that function (no code with "
          "the whole image out, and none with it: so-ambig declines the binding)" + PORT,
          patched and dcc._parse_so(bytes(symt))[P + "twin"][1] != dcc._parse_so(loose)[P + "twin"][1] and
          alone is None and dcc.answer(Q, files) is None, "%r %r" % (alone, dcc.answer(Q, files)))
    # two libraries exporting one JNI name (the other track's ambiguity: two .so bodies of one symbol)
    dx = chain_dex(_emit_long("dual", 5), [(LAB, "dual", "J", ["J"], 0x109, False)])
    ab = members(apk(dx, {"lib/x86_64/liba.so": r3("dual_a"), "lib/x86_64/libb.so": r3("dual_b")}))
    ac = members(apk(dx, {"lib/x86_64/liba.so": r3("dual_a"), "lib/x86_64/libc.so": r3("dual_c")}))
    aa = members(apk(dx, {"lib/x86_64/liba.so": r3("dual_a"), "lib/x86_64/libz.so": r3("dual_a")}))
    check("L/two libraries define one JNI name with bodies that disagree -> no code (the shipped readers alone: %s)"
          % code_of(legacy_alone(ab)), dcc.answer(Q, ab) is None)
    # since the port: two different bodies of one machine binding one JNI method are None whatever they compute
    # (so-ambig, x17's principle: which library a device loads is not in the bytes)
    check("L/... two different bodies that agree -> no code (so-ambig: two .so bodies of one machine)" + PORT,
          dcc.answer(Q, ac) is None, repr(dcc.answer(Q, ac)))
    check("L/... one body under two names -> its code under the judged key", judged_or_unsure(dcc.answer(Q, aa), "ANS-%016X" % 6))
    saved = nib.MAX_IMAGE_CALLS
    nib.MAX_IMAGE_CALLS = 0                        # the whole image is not asked: every body is read by the legacy reader
    try:
        r_ab, r_ac = dcc.answer(Q, ab), dcc.answer(Q, ac)
    finally:
        nib.MAX_IMAGE_CALLS = saved
    check("L/... with the whole image out (its cap at 0): disagreeing bodies -> no code, agreeing bodies -> no code "
          "(so-ambig)" + PORT, r_ab is None and r_ac is None, "%r %r" % (r_ab, r_ac))
    # ART's resolution: a framework (undefined) method never binds; static/instance mismatch and a virtual override
    triv = {"lib/x86_64/libtriv.so": r3("triv")}
    nat_inc = [(LAB, "inc", "J", ["J"], 0x109, False)]

    def emit_other(a, d, mids):
        a.const_wide(0, 5)
        a.invoke(0x71, d.m("Lcom/huntress/kb2/Other;", "inc", "J", ["J"]), [0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_other, nat_inc), triv))
    check("L/a call to a method the delivery does not define never binds to a native export by its name: no code",
          dcc.answer(Q, files) is None)
    check("L/... (the hole) the shipped readers alone never answer NativeLab_inc's code plain for it (so-ambig binds "
          "only its own exact name)" + PORT, not plain_is(legacy_alone(files), "ANS-%016X" % 28), repr(legacy_alone(files)))

    def emit_virtual(a, d, mids):
        a.new_instance(5, d.t(LAB))
        a.const_wide(0, 5)
        a.invoke(0x6E, mids["inc"], [5, 0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_virtual, nat_inc), triv))
    check("L/a static native invoked as an instance method (IncompatibleClassChangeError) -> no code",
          dcc.answer(Q, files) is None)
    sublab = "Lcom/huntress/kb2/SubLab;"

    def emit_virtual2(a, d, mids):
        d.extends(sublab, LAB)
        d.define(sublab, d.m(sublab, "inc", "J", ["J"]), 0x1, virtual=True)
        emit_virtual(a, d, mids)
    files = members(apk(chain_dex(emit_virtual2, [(LAB, "inc", "J", ["J"], 0x101, True)]), triv))
    check("L/an instance native a subclass overrides (virtual dispatch decides) -> no code", dcc.answer(Q, files) is None)
    files = members(apk(chain_dex(emit_virtual, [(LAB, "inc", "J", ["J"], 0x101, True)]), triv))
    check("L/... the same instance native with no override -> its code (image only: unsure)",
          opts_of(dcc.answer(Q, files)) == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % 28)]))
    # the split look-ahead's x17 shape inside ONE package: the Day 23 libarena.so (exporting
    # ...d15...NativeLibrarySecrets_nativeShare) listed before the Day 25 one the dex binds (...d16...JNIBoundary_
    # nativeShare); the shipped reader's suffix match takes the first `_nativeShare` it meets
    d25 = _saved_glob("day-25/mobile-android-*/mastery/artifact/delivery-06/*.apk")
    so23 = _saved_so("day-23/mobile-android-*/mastery/artifact/delivery-05/*.apk")
    if d25 and so23 is not None:
        base = members(d25[0].read_bytes())
        mixed = {k: v for k, v in base.items() if not k.endswith(".so")}
        mixed["lib/x86_64/libaaa.so"] = so23
        mixed.update({k: v for k, v in base.items() if k.endswith(".so")})
        want25 = json.loads((d25[0].parents[2] / "key.json").read_text())["answers"]["set6.answer"]
        # since the port: two libraries of one machine define the binding key `_nativeShare` differently (so-ambig's
        # round 1, a required None in tests/test_day27_so_ambig_mobile.py [4]), so the call declines
        check("L/two libraries whose JNI names share the method name (Day 23's beside Day 25's): no code (so-ambig: two "
              ".so bodies define the binding key differently)" + PORT, dcc.answer(Q, mixed) is None,
              repr(dcc.answer(Q, mixed)))
        la = legacy_alone(mixed)
        check("L/... (the hole) the shipped readers alone never answer Day 23's export plain" + PORT,
              la is None or labels.is_unsure(la) or la == want25, repr(la))
    else:
        print("SKIP L/x17 shape (saved Day 23/25 APKs absent)")
    # the runner's files hold each member twice (`<delivery> -> <member>` and `<member>`): nothing changes
    for libs, fn, nat in (({"lib/x86_64/libkb2.so": fx("kb2_jni_x86_64.so")}, None, [NAT_MIX]), (triv, "inc", nat_inc)):
        blob = apk(chain_dex(emit_mix_string("hello native") if fn is None else _emit_long(fn, 5), nat), libs)
        plain = members(blob)
        runner = dict(plain)
        runner["d.apk"] = blob
        for k, v in plain.items():
            runner["d.apk -> " + k] = v
        a1, a2 = dcc.answer(Q, plain), dcc.answer(Q, runner)
        check("L/the runner's files (each member also under '<delivery> -> <member>') answer as the members (%s)"
              % ("image only" if fn is None else "legacy-proven"), a1 == a2 and a1 is not None, "%r %r" % (a1, a2))


def test_r3_state_and_layouts():
    """Review items 3 and 4 (state escaping through the heap; layouts agreeing on address bits), the pinned vs copied
    array item and the stale JNI_OnLoad reference."""
    heap = {"lib/x86_64/libheap.so": r3("heap")}

    def emit_tick2(a, d, mids):
        a.const_wide(0, 0x1000)
        a.invoke(0x71, mids["tick"], [0, 1])
        a.move_result_wide(2)
        a.invoke(0x71, mids["tick"], [0, 1])
        a.move_result_wide(4)
        a.binop(0xA2, 2, 2, 4)
        a.const_wide(4, 0x0123456789ABCDEF)
        a.binop(0xA2, 2, 2, 4)
        tail_format(a, d, 2)
    nat = [(LAB, "tick", "J", ["J"], 0x109, False), (LAB, "peek", "J", ["J"], 0x109, False)]
    check("L/heap: a call that steps a counter the constructor malloc'd -> no code (review: the first call's value "
          "every time, ANS-0123456789ABCDEF under +native-image; a device ANS-0123456789ABCDCE)",
          dcc.answer(Q, members(apk(chain_dex(emit_tick2, nat), heap))) is None)
    check("L/... the engine declines the write into the load phase's heap block itself",
          declines(ni.call_jni, r3("heap"), P + "tick", [("J", 1)], "J"))
    o = opts_of(dcc.answer(Q, members(apk(chain_dex(_emit_long("peek", 0x1000), nat), heap))))
    check("L/... a call that only READS the constructor's heap block -> no code (so-ambig's constructor rule; the "
          "bridge alone read the loaded value, unsure)" + PORT, o is None, repr(o))
    so = r3("addr")
    for fn in ("imageBits", "heapLow", "stackLow", "refBits", "envLow"):
        check("L/an address-derived result (%s) differs between the two layouts: declines" % fn,
              declines(ni.call_jni, so, P + fn, [("J", 5)], "J"))
    check("L/a 'round load address' emulator check (review's addr_bits) sees device-like bases in both layouts: the "
          "device leg x+0x2222, never the emulator leg", ni.call_jni(so, P + "addr", [("J", 5)], "J").value == 5 + 0x2222)
    def emit_null(a, d, mids):
        a.const4(2, 0)                               # Dalvik's null: the integer 0 in a reference register
        a.invoke(0x71, mids["isNull"], [2])
        a.move_result_wide(0)
        a.new_instance(3, d.t(LAB))                  # an object
        a.invoke(0x71, mids["isNull"], [3])
        a.move_result_wide(4)
        a.const_wide(6, 16)
        a.binop(0x9D, 0, 0, 6)                       # mul-long v0, v0, v6
        a.binop(0x9B, 0, 0, 4)                       # add-long v0, v0, v4
        tail_format(a, d, 0)
    o = opts_of(dcc.answer(Q, members(apk(chain_dex(emit_null, [(LAB, "isNull", "J", ["Ljava/lang/Object;"], 0x109,
                                                                 False)]), {"lib/x86_64/libaddr.so": so}))))
    check("L/a null and an object argument: NULL then non-NULL to the native, two evaluations (never one memo "
          "entry) -> 1 then 2", o == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % 0x12)]), repr(o))
    A, B = ni._LAYOUTS
    hA, hB = A["heap"] + A["heap_off"], B["heap"] + B["heap_off"]
    sA, sB = A["stack"] - A["stack_gap"], B["stack"] - B["stack_gap"]
    check("L/layouts: image bases complementary in bits 12-35, one below 2^39 and one above it",
          ((A["image"] ^ B["image"]) >> 12) & 0xFFFFFF == 0xFFFFFF and
          min(A["image"], B["image"]) < (1 << 39) <= max(A["image"], B["image"]))
    check("L/layouts: first heap block and stack top 16-aligned and complementary in bits 4-35",
          not (hA | hB | sA | sB) & 15 and ((hA ^ hB) >> 4) & 0xFFFFFFFF == 0xFFFFFFFF and
          ((sA ^ sB) >> 4) & 0xFFFFFFFF == 0xFFFFFFFF)
    check("L/layouts: references complementary in bits 2-11, one run with ART's local-reference kind bits (01)",
          ((A["handle"] ^ B["handle"]) >> 2) & 0x3FF == 0x3FF and {A["handle"] & 3, B["handle"] & 3} == {0, 1})
    pin = r3("pin")
    for fn, why in (("pin", "a modified elements buffer read back through GetByteArrayRegion"),
                    ("pinSet", "SetByteArrayRegion while an elements buffer is held"),
                    ("pinTwice", "a second elements buffer of one array")):
        check("L/pinned vs copied arrays: %s declines" % why, declines(ni.call_jni, pin, P + fn, [("arr:B", [0x41, 2])], "J"))
    stale_nat = [(LAB, "stale", "J", ["J"], 0x109, False), (LAB, "fresh", "J", ["J"], 0x109, False)]
    libs = {"lib/x86_64/libstale.so": r3("stale")}
    check("L/a JNI local reference JNI_OnLoad kept in a global is gone once it returned: using it declines",
          dcc.answer(Q, members(apk(chain_dex(_emit_long("stale", 5), stale_nat), libs))) is None)
    # since the port: the library's JNI_OnLoad is not provably inert (so-ambig's rule 1 declines every binding), so the
    # whole image's reading of the export stands only demoted, +load-modelled@onload
    ans = dcc.answer(Q, members(apk(chain_dex(_emit_long("fresh", 5), stale_nat), libs)))
    check("L/... a sibling native that does not use it -> no code (so-ambig: the library's JNI_OnLoad is not proven "
          "inert; the bridge alone answered it under the judged key)" + PORT, ans is None, repr(ans))
    # a PT_LOAD whose file offset and address are not congruent modulo the page: bionic would map it shifted
    b = bytearray(fx("kb2_jni_x86_64.so"))
    phoff = struct.unpack_from("<Q", b, 0x20)[0]
    for i in range(struct.unpack_from("<H", b, 0x38)[0]):
        o = phoff + 56 * i
        if struct.unpack_from("<I", b, o)[0] == 1 and struct.unpack_from("<Q", b, o + 8)[0] >= 8:
            struct.pack_into("<Q", b, o + 8, struct.unpack_from("<Q", b, o + 8)[0] - 8)
            break
    try:
        ni.load(bytes(b))
        refused = ""
    except ni.EmulationError as e:
        refused = str(e)
    check("L/a PT_LOAD whose p_offset and p_vaddr are not congruent modulo the page is refused at load",
          "congruent" in refused, refused)


def test_r3_demotions():
    """Review items 5 and 6 (regressions: a benign multi-ABI APK and a benign constructor were None)."""
    nat_inc = [(LAB, "inc", "J", ["J"], 0x109, False)]
    dinc = chain_dex(_emit_long("inc", 5), nat_inc)
    want = "ANS-%016X" % 28
    arm7 = fx("kb2_r3_triv_armv7a.o")
    files = members(apk(dinc, {"lib/x86_64/libabi.so": r3("triv"), "lib/armeabi-v7a/libabi.so": arm7}))
    ans = dcc.answer(Q, files)
    # KB-2 fix round 3 (the review of 18ab31d, item 3): so-ambig binds the 64-bit export and its SO_ELF32_LEGS "ignore"
    # lets it answer beside a 32-bit leg no emulator runs (the shipped tree's answer); +abi-unverified is kept for a
    # 32-bit leg with a JNI_OnLoad (M/10) and for a long-name binding so-ambig does not see (declined: O/3)
    check("L/benign multi-ABI (x86_64 + an armeabi-v7a build the engine cannot load) -> the x86_64 reading under the "
          "judged key, as on the shipped tree (SO_ELF32_LEGS 'ignore'; fix round 3 item 3; fix rounds 1-2: unsure "
          "+abi-unverified)", judged_or_unsure(ans, want) and dcc.recover(files) in (None, want), repr(ans))
    saved = dcc.SO_ELF32_LEGS
    dcc.SO_ELF32_LEGS = "decline"
    try:
        o = opts_of(dcc.answer(Q, files))
    finally:
        dcc.SO_ELF32_LEGS = saved
    check("L/... with SO_ELF32_LEGS 'decline' the 32-bit leg keeps its demotion (+abi-unverified), never plain",
          o == ("mobile.codec/analysis+abi-unverified", [("analysis:dex-chain+abi-unverified", want)]), repr(o))
    check("L/... x86_64 alone -> the judged key's reading",
          judged_or_unsure(dcc.answer(Q, members(apk(dinc, {"lib/x86_64/libabi.so": r3("triv")}))), want))
    check("L/... x86_64 + arm64 (both read, both agree) -> the judged key's reading",
          judged_or_unsure(dcc.answer(Q, members(apk(dinc, {"lib/x86_64/libabi.so": r3("triv"),
                                                            "lib/arm64-v8a/libabi.so": r3("triv", "arm64")}))), want))
    files = members(apk(dinc, {"lib/x86_64/libctor.so": r3("ctorlog")}))
    # since the port: so-ambig declines every binding beside DT_INIT / DT_INIT_ARRAY (SO_CTORS), so the reading the
    # whole image proves stands only demoted, +load-modelled@ctor
    check("L/a benign constructor that logs (liblog modelled since fix round 1) -> no code (so-ambig's constructor "
          "rule; the bridge alone read it exactly, the judged key's reading)" + PORT,
          dcc.answer(Q, files) is None, repr(dcc.answer(Q, files)))
    files = members(apk(dinc, {"lib/x86_64/libctor.so": fx("kb2_f1_ctornew_x86_64.so")}))
    o = opts_of(dcc.answer(Q, files))
    check("L/a benign constructor the model cannot run (operator new) -> no code (so-ambig's constructor rule; the "
          "bridge alone gave the export's reading unsure under +ctor-unverified)" + PORT,
          o is None and dcc.recover(files) is None, repr(o))
    check("L/the demoted keys are never judged plain by accident: no ledger row names them",
          labels.pick("mobile.codec/analysis+abi-unverified", [("analysis:dex-chain+abi-unverified", want)]) != want and
          labels.pick("mobile.codec/analysis+ctor-unverified", [("analysis:dex-chain+ctor-unverified", want)]) != want)


def test_r3_budgets():
    """Review items 7 and 8 (per-call setup charged to no budget; work inside the libc model not counted) and the
    test gap 'a chain's cumulative native time'."""
    nat_inc = [(LAB, "inc", "J", ["J"], 0x109, False)]
    triv = {"lib/x86_64/libtriv.so": r3("triv")}
    files = members(apk(chain_dex(emit_loop("inc", 200), nat_inc), triv))
    t = time.perf_counter()
    off = legacy_alone(files)
    t_off = time.perf_counter() - t
    with _CountCalls() as c:
        t = time.perf_counter()
        on = dcc.answer(Q, files)
        t_on = time.perf_counter() - t
    # KB-2 fix round 2 (the review of 4250749, item b): past the cap the calls are 'unchecked', so the shipped readers'
    # code is demoted (+image-unchecked@inc), never plain (the cap reached by a per-character loop kept it plain)
    check("L/a native called 200 times in a dex loop: the shipped readers' code, demoted +image-unchecked@inc past the "
          "cap, the whole image asked %d times (the cap is 16 a delivery), %.0f ms against %.0f ms for the shipped "
          "readers alone" % (c.n, 1000 * t_on, 1000 * t_off),
          opts_of(on) is not None and opts_of(on)[0] == "mobile.codec/analysis+image-unchecked@inc" and
          opts_of(on)[1][0][1] == code_of(off) and code_of(off) is not None and nib.MAX_IMAGE_CALLS == 16 and
          c.n == 16 and t_on < t_off + 0.3, repr(on))
    files = members(apk(chain_dex(emit_loop("inc", 50, arg=1, chained=False), nat_inc), triv))
    with _CountCalls() as c:
        ans = dcc.answer(Q, files)
    check("L/an identical call repeated 50 times is evaluated by the whole image once per delivery (%d)" % c.n,
          c.n == 1 and judged_or_unsure(ans, "ANS-%016X" % 8), repr(ans))
    span = ni.load(fx("kb2_jni_x86_64.so")).hi - ni.load(fx("kb2_jni_x86_64.so")).lo

    def emit_two(a, d, mids):
        a.const_string(2, d.s("one"))
        a.invoke(0x71, mids["mixString"], [2])
        a.move_result_wide(0)
        a.const_string(3, d.s("two"))
        a.invoke(0x71, mids["mixString"], [3])
        a.move_result_wide(4)
        a.binop(0xA2, 0, 0, 4)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_two, [NAT_MIX]), {"lib/x86_64/libkb2.so": fx("kb2_jni_x86_64.so")}))
    saved = nib.TOTAL_SETUP_BYTES
    try:
        nib.TOTAL_SETUP_BYTES = 2 * span           # room for ONE evaluation (two runs) of this library
        one = dcc.answer(Q, files)
        nib.TOTAL_SETUP_BYTES = 4 * span           # room for two
        two = dcc.answer(Q, files)
    finally:
        nib.TOTAL_SETUP_BYTES = saved
    want = "ANS-%016X" % (m_mix_string("one") ^ m_mix_string("two"))
    check("L/past the delivery's budget of image bytes to map, an image-only call declines; with room it answers",
          one is None and opts_of(two) == (IMG_KEY[0], [(IMG_KEY[1], want)]), "%r %r" % (one, two))
    usage = {}
    t = time.perf_counter()
    dec = declines(ni.call_jni, r3("burn"), P + "burn", [("J", 5)], "J", max_blocks=nib.PER_RUN_BLOCKS,
                   max_mem=nib.PER_RUN_MEM, usage=usage)
    dt = time.perf_counter() - t
    check("L/work inside the modelled memcpy counts: a 400 KB memcpy loop declines by its budget (%.0f ms; review: "
          "1.4-1.6 s per call)" % (1000 * dt), dec and dt < 0.5, repr(usage))

    def emit_burn3(a, d, mids):
        a.const_wide(0, 5)
        for _ in range(3):
            a.invoke(0x71, mids["burn"], [0, 1])
            a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_burn3, [(LAB, "burn", "J", ["J"], 0x109, False)]),
                        {"lib/x86_64/libburn.so": r3("burn")}))
    t = time.perf_counter()
    res = dcc.answer(Q, files)
    dt = time.perf_counter() - t
    check("L/... three such calls in one chain: no code, quickly (%.0f ms; review: 4.0 s)" % (1000 * dt),
          res is None and dt < 1.0)


# ============================================================================== M. fix round 1 (review of e281f95)
DECOY = "ANS-DEC0DEC0DEC0DEC0"
NAT_MIXJ = (LAB, "mix", "J", ["J"], 0x109, False)
NAT_INC = (LAB, "inc", "J", ["J"], 0x109, False)
Q_E2E = {"id": "answer", "qid": "answer", "answer_id": "answer",
         "answer_format": {"kind": "pattern", "syntax": "ANS- followed by exactly 16 uppercase hexadecimal characters"},
         "question": "Recover the backend answer code for this case. Submit only the exact answer code."}
_CS = []


def f1(name):
    return fx("kb2_f1_%s_x86_64.so" % name)


def plain(ans):
    return isinstance(ans, str) and not labels.is_unsure(ans)


def chain_dex2(emit, natives, extra_strings=(), regs=24):
    """chain_dex, with extra strings in the dex's string table (a decoy code in clear)."""
    d = NDex()
    a = Asm()
    mids = {}
    for (cls, name, ret, params, flags, virtual) in natives:
        mids[name] = d.m(cls, name, ret, params)
        d.define(cls, mids[name], flags, virtual=virtual)
    for s in extra_strings:
        d.s(s)
    emit(a, d, mids)
    units = a.finish()
    run = d.m("Lcom/huntress/kb2/C;", "run", STRING, [])
    d.define("Lcom/huntress/kb2/C;", run, 0x9, units, regs, 0, 6)
    return d.build()


import functools as _functools          # noqa: E402
import importlib.util as _ilu             # noqa: E402

# B-240 carry: four tests below drive codec_search through tests/day21_mobile_specimens.py, which reads the Huntress
# judge ledger (challenges/_ledger). That helper was archived, not carried, so they are reported as not run, by name.
_SPECIMENS = _ilu.find_spec("day21_mobile_specimens") is not None
_SPECIMENS_WHY = ("needs tests/day21_mobile_specimens.py and the Huntress judge ledger it reads (archived Huntress "
                  "helper, not carried into the master)")


def _needs_specimens(fn):
    @_functools.wraps(fn)
    def run(*args, **kwargs):
        if not _SPECIMENS:
            if "pytest" in sys.modules:
                import pytest
                pytest.skip(_SPECIMENS_WHY)
            print(f"SKIP {fn.__name__}: {_SPECIMENS_WHY}")
            return None
        return fn(*args, **kwargs)
    return run


def codec_search_mod():
    if not _CS:
        import day21_mobile_specimens as S
        C, _lab = S._load(str(ROOT / "solvers"), "real")
        _CS.append(C)
    return _CS[0]


def runner_files(blob, name="d.apk"):
    """The files tools/run.py hands a solver for one delivery: the delivery, '<name> -> <member>' and '<member>'."""
    out = {name: blob}
    for k, v in members(blob).items():
        out["%s -> %s" % (name, k)] = v
        out.setdefault(k, v)
    return out


class _Partial(dict):
    """The runner's partial answers, recording every value ever written (a plain decoy there would be sent)."""

    def __init__(self):
        super().__init__()
        self.seen = []

    def update(self, *a, **k):
        d = dict(*a, **k)
        self.seen += list(d.values())
        super().update(d)

    def __setitem__(self, k, v):
        self.seen.append(v)
        super().__setitem__(k, v)


def solve_e2e(blob, deliveries=1):
    """codec_search.solve_set as tools/run.py calls it (runner-shaped files, the real ledger):
    (answer, LAST, partial answers)."""
    C = codec_search_mod()
    partial = _Partial()
    attempt = {"artifacts": [{} for _ in range(deliveries)]}
    with contextlib.redirect_stderr(io.StringIO()):
        out = C.solve_set([dict(Q_E2E)], runner_files(blob), {"set": 1, "delivery": blob, "delivery_name": "d.apk",
                                                             "attempt": attempt, "partial": partial})
    return out.get("answer"), dict(C.LAST), partial


def _never_plain_but(partial, allowed):
    return all(not plain(v) or v == allowed for v in partial.seen)


@_needs_specimens
def test_f1_fallthrough():
    """Issue 1a: a dex chain that is not read to one code beside a code in clear: codec_search's generic search found
    the code in clear and answered it PLAIN under the judged apk-string:dex (five shapes of the review)."""
    C = codec_search_mod()
    try:
        labels.parse("??{}")
    except Exception:
        pass
    x = 0x10
    nat_dual = [(LAB, "dual", "J", ["J"], 0x109, False)]
    disagree = {"lib/x86_64/liba.so": r3("dual_a"), "lib/x86_64/libb.so": r3("dual_b")}
    blob = apk(chain_dex2(_emit_long("dual", x), nat_dual, extra_strings=(DECOY,)), disagree)
    # since the port onto so-ambig: so-ambig's _beside_analysis gave this package-look decoy its own key
    # (`<key>:beside-analysis`) and _analysis_unread kept it unsure. B-229 fix round 2 (fail closed on the set path):
    # an `analysis` document's code is what its dex chain computes, so solve_set withdraws an unsure answer offering
    # a value no chain method computed. The decoy is now never offered, not even unsure, nor in the partial answers.
    def decoy_gone(ans, partial):
        return ans is None and not any(DECOY in str(v) for v in partial.seen)

    for n in (1, 5):
        ans, last, partial = solve_e2e(blob, n)
        check("M/1a: two libraries that disagree + a decoy in clear (%d delivery set): no answer, the decoy never "
              "offered (B-229 fail closed; review: PLAIN apk-string:dex; so-ambig: unsure)" % n,
              decoy_gone(ans, partial) and last.get("analysis_unread"), "%r %r" % (ans, partial.seen))
    # the emulator check: the whole image ran the device leg and failed, the legacy reader read the emulator leg
    nat_probe = [(LAB, "probe", "J", ["J"], 0x109, False)]
    blob = apk(chain_dex2(_emit_long("probe", 0x1000), nat_probe, extra_strings=(DECOY,)),
               {"lib/x86_64/libemu.so": f1("emu")})
    ans, _last, partial = solve_e2e(blob)
    check("M/1a: an emulator-check native the bridge declines + a decoy in clear -> the decoy never offered "
          "(B-229 fail closed)", decoy_gone(ans, partial), repr(ans))
    # a static native invoked as an instance method (an ambiguous resolution) + a decoy in clear
    def emit_virtual(a, d, mids):
        a.new_instance(5, d.t(LAB))
        a.const_wide(0, 5)
        a.invoke(0x6E, mids["inc"], [5, 0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    blob = apk(chain_dex2(emit_virtual, [NAT_INC], extra_strings=(DECOY,)), {"lib/x86_64/libtriv.so": r3("triv")})
    ans, _last, partial = solve_e2e(blob)
    check("M/1a: a static/instance mismatch + a decoy in clear -> the decoy never offered (B-229 fail closed)",
          decoy_gone(ans, partial), repr(ans))
    # control: the dex chain reads its one code: the judged reading, the decoy never looked at
    blob = apk(chain_dex2(_emit_long("inc", 5), [NAT_INC], extra_strings=(DECOY,)), {"lib/x86_64/libtriv.so": r3("triv")})
    ans, _last, _partial = solve_e2e(blob)
    check("M/1a: control: a chain read to its one code beside a decoy in clear -> the chain's code (judged key)",
          judged_or_unsure(ans, "ANS-%016X" % 28), repr(ans))
    # the helper itself
    au = C._analysis_unread
    p_ans, p_key = au("ANS-0123456789ABCDEF", "mobile.codec/apk-string:dex")
    u_ans, u_key = au(labels.unsure("mobile.codec/apk-string:dex:base64", [("apk-string:dex:base64", DECOY)]),
                      "mobile.codec/apk-string:dex:base64")
    c_ans, c_key = au(labels.unsure("mobile.codec/x#candidates", [("h1", DECOY), ("h2", "ANS-0000000000000001")]),
                      "mobile.codec/x#candidates")
    b_in = labels.unsure("mobile.codec/apk-string:dex:beside-analysis", [("apk-string:dex", DECOY)])
    b_ans, b_key = au(b_in, "mobile.codec/apk-string:dex:beside-analysis")
    check("M/1a: _analysis_unread: a plain reading -> unsure under <key>:analysis-unread as `code`; an unsure one "
          "re-keyed with its options; a candidate key keeps its mark; None stays None; never doubled; so-ambig's "
          ":beside-analysis key kept as it is (the port)",
          opts_of(p_ans) == ("mobile.codec/apk-string:dex:analysis-unread", [("code", "ANS-0123456789ABCDEF")]) and
          p_key == "mobile.codec/apk-string:dex:analysis-unread" and
          opts_of(u_ans) == ("mobile.codec/apk-string:dex:base64:analysis-unread", [("apk-string:dex:base64", DECOY)])
          and c_key == "mobile.codec/x:analysis-unread#candidates" and labels.is_candidate(c_ans) and
          au(None, "k") == (None, "k") and au(p_ans, p_key)[1] == p_key and b_ans == b_in and
          b_key == "mobile.codec/apk-string:dex:beside-analysis", "%r %r %r %r" % (p_ans, u_ans, c_ans, b_ans))
    check("M/1a: the :analysis-unread keys are never judged plain by accident (no ledger row names them)",
          labels.pick("mobile.codec/apk-string:dex:analysis-unread", [("code", DECOY)]) != DECOY)


@_needs_specimens
def test_f1_demotions():
    """Issues 1b and 7: a JNI_OnLoad the model cannot run, a helper library, a class defined twice: the legacy reading
    stays (demoted where something is unknown) instead of a decline of the whole delivery."""
    x = 0x10
    want = "ANS-%016X" % (x * 7 + 5)
    dmix = chain_dex2(_emit_long("mix", x), [NAT_MIXJ])
    dmix_decoy = chain_dex2(_emit_long("mix", x), [NAT_MIXJ], extra_strings=(DECOY,))
    # since the port onto so-ambig: a JNI_OnLoad that is not provably inert (it calls GetEnv and the logger) makes
    # so-ambig decline every binding, so the export's reading (which the whole image proves) stands only demoted,
    # +load-modelled@onload; never the decoy
    files = members(apk(dmix, {"lib/x86_64/libmix.so": f1("onlog")}))
    check("M/1b: a JNI_OnLoad that logs (liblog modelled) beside the export -> no code (so-ambig: a JNI_OnLoad not "
          "proven inert; the bridge alone read it exactly; review: None, and the decoy PLAIN end to end)" + PORT,
          dcc.answer(Q, files) is None, repr(dcc.answer(Q, files)))
    ans, _last, partial = solve_e2e(apk(dmix_decoy, {"lib/x86_64/libmix.so": f1("onlog")}), 5)
    check("M/1b: ... end to end beside a decoy in clear, a five-delivery set: never the decoy plain (only unsure under "
          "so-ambig's :beside-analysis)" + PORT,
          unsure_or_none(ans) and not plain_is(ans, DECOY) and _never_plain_but(partial, None), repr(ans))
    k_glob = ("mobile.codec/analysis+onload-unverified@jni-newglobalref",
              [("analysis:dex-chain+onload-unverified@jni-newglobalref", want)])
    files = members(apk(dmix, {"lib/x86_64/libmix.so": f1("onglob")}))
    check("M/1b: a JNI_OnLoad that caches a global reference (not modelled) -> no code (so-ambig: a JNI_OnLoad not "
          "proven inert; the bridge alone gave the export's reading unsure under +onload-unverified@jni-newglobalref)"
          + PORT, dcc.answer(Q, files) is None and dcc.recover(files) is None and k_glob[0].endswith("newglobalref"),
          repr(dcc.answer(Q, files)))
    ans, _last, partial = solve_e2e(apk(dmix_decoy, {"lib/x86_64/libmix.so": f1("onglob")}))
    check("M/1b: ... end to end beside a decoy in clear: never the decoy plain" + PORT,
          unsure_or_none(ans) and not plain_is(ans, DECOY) and _never_plain_but(partial, None), repr(ans))
    dinc = chain_dex2(_emit_long("inc", 5), [NAT_INC])
    w28 = "ANS-%016X" % 28
    for helper, k in (("helper", None), ("helperglob", "jni-newglobalref")):
        files = members(apk(dinc, {"lib/x86_64/libtriv.so": r3("triv"), "lib/x86_64/libhelper.so": f1(helper)}))
        ans = dcc.answer(Q, files)
        # since the port: the helper's JNI_OnLoad is not provably inert, so so-ambig declines every binding
        check("M/7: a helper library whose JNI_OnLoad %s, beside the binding library -> no code (so-ambig: a JNI_OnLoad "
              "not proven inert; the bridge alone gave %s)" % ("logs" if k is None else "caches a global reference",
                                                               "the judged key's code" if k is None else
                                                               "unsure +onload-unverified@" + k) + PORT,
              ans is None, repr(ans))
    files = members(apk(dmix, {"lib/x86_64/libmix.so": f1("onlogreg")}))
    o = opts_of(dcc.answer(Q, files))
    check("M/1b: a JNI_OnLoad that logs and THEN registers mix elsewhere -> no code (so-ambig: a JNI_OnLoad not proven "
          "inert beside the export; the bridge alone read the registered function, image only, unsure), never the decoy "
          "export" + PORT, o is None, repr(o))
    # a class defined in two dex members
    d2 = NDex()
    d2.define(LAB, d2.m(LAB, "mix", "J", ["J"]), 0x109)
    files = members(apk(dmix_decoy, {"lib/x86_64/libmix.so": fx("kb2_r3_dual_a_x86_64.so")}))
    files = members(apk(dmix, {"lib/x86_64/libmix.so": f1("onlog")}))
    files["classes2.dex"] = d2.build()
    # since the port onto KB-7: a class two dex members define is never run or initialized by the VM (dex_float's
    # dup rule: a device loads ONE copy), so the chain declines; never the decoy
    check("M/1b: the native's class also in classes2.dex, the definitions agree -> no code (KB-7: a class two dex "
          "members define is not run; review: None, and the decoy PLAIN end to end)" + PORT,
          dcc.answer(Q, files) is None, repr(dcc.answer(Q, files)))
    d3 = NDex()
    d3.define(LAB, d3.m(LAB, "mix", "J", ["J"]), 0x9)              # a stale copy that is no native
    files["classes2.dex"] = d3.build()
    o = opts_of(dcc.answer(Q, files))
    check("M/1b: ... the definitions differ (classes2.dex's is no native): no code (KB-7's dup rule; the bridge alone "
          "gave +dup-class)" + PORT, dcc.answer(Q, files) is None, repr(o))
    blob = apk(dmix_decoy, {"lib/x86_64/libmix.so": f1("onlog")}, )
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for n in zin.namelist():
            zout.writestr(n, zin.read(n))
        zout.writestr("classes2.dex", d3.build())
    ans, _last, partial = solve_e2e(buf.getvalue())
    check("M/1b: ... end to end beside a decoy in clear: never the decoy plain (the chain declines, the decoy only "
          "unsure under so-ambig's :beside-analysis or :analysis-unread)" + PORT,
          unsure_or_none(ans) and not plain_is(ans, DECOY) and _never_plain_but(partial, None), repr(ans))


def test_f1_image_failed():
    """Issue 2: the whole image RAN a call the legacy reader read and failed (it followed another path): the legacy
    reading is not taken. An image that ran out of work demotes; one that was not run keeps the legacy reading."""
    nat_probe = [(LAB, "probe", "J", ["J"], 0x109, False)]
    arg = 0x1000
    emu_leg = "ANS-%016X" % (arg ^ 0x1111)
    for name in ("emu", "emuloose"):
        files = members(apk(chain_dex2(_emit_long("probe", arg), nat_probe), {"lib/x86_64/libemu.so": f1(name)}))
        alone = legacy_alone(files)
        check("M/2: an emulator check on the code address (%s): the legacy engine's fixed base takes the emulator leg "
              "(%s), the whole image the device leg and fails -> no code (review: the emulator leg PLAIN)"
              % (name, code_of(alone)), dcc.answer(Q, files) is None and dcc.recover(files) is None and
              (name == "emuloose" or code_of(alone) == emu_leg), repr(dcc.answer(Q, files)))
    try:
        ni.call_jni(f1("emu"), P + "probe", [("J", arg)], "J", max_blocks=nib.PER_RUN_BLOCKS, max_mem=nib.PER_RUN_MEM)
        kind = None
    except ni.EmulationError as e:
        kind = type(e)
    check("M/2: ... the engine's failure there is an ordinary EmulationError (no SetupError, no BudgetError)",
          kind is ni.EmulationError)
    files = members(apk(chain_dex2(_emit_long("probe", arg), nat_probe), {"lib/x86_64/libemu.so": f1("emuspin")}))
    o = opts_of(dcc.answer(Q, files))
    check("M/2: ... whose device leg spins past the image's work budget -> the legacy reading only unsure under "
          "+image-unchecked@probe", o == ("mobile.codec/analysis+image-unchecked@probe",
                                          [("analysis:dex-chain+image-unchecked@probe", emu_leg)]), repr(o))
    try:
        ni.call_jni(f1("emuspin"), P + "probe", [("J", arg)], "J", max_blocks=nib.PER_RUN_BLOCKS,
                    max_mem=nib.PER_RUN_MEM)
        kind = None
    except ni.EmulationError as e:
        kind = type(e)
    so = r3("triv")
    aps2 = _patch_dyn_tag(fx("kb2_jni_x86_64.so"), 0x6FFFFFF9, 0x60000011)
    kinds = []
    # B-241: a float argument is modelled now; one that is not a number is still an argument the model does not take
    for fn, a in ((lambda: ni.call_jni(so, P + "inc", [("F", "1")], "J"), None),
                  (lambda: ni.call_jni(aps2, P + "mixString", [("str", "a")], "J"), None),
                  (lambda: ni.call_jni(so, P + "inc", [("arr:B", [1]), ("arr:B", None)], "J"), None)):
        try:
            fn()
            kinds.append(None)
        except ni.EmulationError as e:
            kinds.append(type(e))
    check("M/2: the error classes: a work budget is BudgetError; a float argument, an image problem and an argument "
          "the model does not take are SetupError", kind is ni.BudgetError and kinds[:2] == [ni.SetupError] * 2,
          "%r %r" % (kind, kinds))
    # not run (a size bound): KB-2 fix round 2 (the review of 4250749, item b): the legacy reading stands only demoted
    saved = nib.MAX_IMAGE_BYTES
    nib.MAX_IMAGE_BYTES = 1000
    try:
        ans = dcc.answer(Q, members(apk(chain_dex2(_emit_long("inc", 5), [NAT_INC]), {"lib/x86_64/libtriv.so": so})))
    finally:
        nib.MAX_IMAGE_BYTES = saved
    check("M/2: a library past the size bounds (the whole image not run): the legacy reading, demoted "
          "+image-unchecked@inc (fix round 2, item b; it stood plain under the judged key)",
          opts_of(ans) == ("mobile.codec/analysis+image-unchecked@inc",
                           [("analysis:dex-chain+image-unchecked@inc", "ANS-%016X" % 28)]), repr(ans))


def test_f1_values():
    """Issues 3, 8, 9: a boxed argument to an Object parameter, a negative jint, Dalvik's compare opcodes."""
    nat = (LAB, "isNull", "J", ["Ljava/lang/Object;"], 0x109, False)
    for v in (0, 5):
        def emit(a, d, mids, v=v):
            lv = d.m(LONG, "valueOf", LONG, ["J"])
            a.const_wide(2, v)
            a.invoke(0x71, lv, [2, 3])
            a.move_result_object(5)
            a.invoke(0x71, mids["isNull"], [5])          # a device passes a non-NULL jobject
            a.move_result_wide(0)
            tail_format(a, d, 0)
        files = members(apk(chain_dex2(emit, [nat]), {"lib/x86_64/libaddr.so": r3("addr")}))
        o = opts_of(dcc.answer(Q, files))
        check("M/3: isNull(Long.valueOf(%d)): a non-NULL object -> 2, image only, unsure (review: PLAIN 1 for 0); the "
              "legacy reader alone declines a boxed value for a reference parameter" % v,
              o == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % 2)]) and legacy_alone(files) is None, repr(o))
    nat_sign = (LAB, "sign", "I", ["J"], 0x109, False)

    def emit_sign(a, d, mids):
        a.const_wide(2, 5)
        a.invoke(0x71, mids["sign"], [2, 3])
        a.move_result(4)
        a.if_testz(0x3A, 4, "neg")                       # if-ltz v4 (5 - 200 < 0 on a device)
        a.const_wide(0, 0xB0B0B0B0B0B0B0B0)
        a.goto16("tail")
        a.label("neg")
        a.const_wide(0, 0xA0A0A0A0A0A0A0A0)
        a.label("tail")
        tail_format(a, d, 0)
    files = members(apk(chain_dex2(emit_sign, [nat_sign]), {"lib/x86_64/libsign.so": f1("negint")}))
    want = "ANS-A0A0A0A0A0A0A0A0"
    check("M/8: a jint native returning -195, then if-ltz: the leg a device takes (review: the other leg PLAIN), with "
          "the bridge and with the legacy reader alone", judged_or_unsure(dcc.answer(Q, files), want) and
          judged_or_unsure(legacy_alone(files), want), "%r %r" % (dcc.answer(Q, files), legacy_alone(files)))
    # the compares: cmp-long 0x31, cmpl-float 0x2d, cmpg-float 0x2e, cmpl-double 0x2f, cmpg-double 0x30
    nan_f, one_f, two_f = 0x7FC00000, 0x3F800000, 0x40000000
    d15, d25, nan_d, zero_d = 0x3FF8000000000000, 0x4004000000000000, 0x7FF8000000000000, 0
    cases = [(0x31, (-1) & M64, 0, True, -1), (0x31, 5, (-7) & M64, True, 1), (0x31, 3, 3, True, 0),
             (0x2D, nan_f, one_f, False, -1), (0x2E, nan_f, one_f, False, 1), (0x2D, two_f, two_f, False, 0),
             (0x2E, one_f, two_f, False, -1), (0x2F, d15, d25, True, -1), (0x30, nan_d, zero_d, True, 1),
             (0x2F, nan_d, zero_d, True, -1), (0x30, d25, d15, True, 1)]

    def emit_cmp(a, d, mids):
        a.const_string(40, d.s("ANS-"))                  # marks run() as an entry of the chain
        a.const16(30, 0)                                 # acc (const/16: a register past v15)
        a.const16(31, 3)
        for op, xv, yv, wide, _r in cases:
            if wide:
                a.const_wide(20, xv)
                a.const_wide(22, yv)
            else:
                a.const32(20, xv)
                a.const32(22, yv)
            a.cmp(op, 24, 20, 22)
            a.binop(0x92, 30, 30, 31)                    # mul-int acc, acc, 3
            a.binop(0x90, 30, 30, 24)                    # add-int acc, acc, r
            a.const16(25, 1)
            a.binop(0x90, 30, 30, 25)                    # + 1 (r + 1 in 0..2)
        a.move16(0, 30)
        a.u.append(0x81 | (0 << 8) | (0 << 12))          # int-to-long v0 <- v0 (12x)
        tail_format(a, d, 0)
    acc = 0
    for *_rest, r in cases:
        acc = acc * 3 + r + 1
    files = members(apk(chain_dex2(emit_cmp, [], regs=48), {}))
    codes = dcc.analysis_codes_ex(files)
    check("M/9: cmp-long, cmpl/cmpg-float and cmpl/cmpg-double by Dalvik's numbering, NaN bias included (review: "
          "cmp-long(-1L, 0L) read +1)", codes == (["ANS-%016X" % acc], 0), repr(codes))


def _wx(so):
    """A copy whose R+X PT_LOAD is also writable (bionic and this engine refuse to load it)."""
    b = bytearray(so)
    phoff = struct.unpack_from("<Q", b, 0x20)[0]
    for i in range(struct.unpack_from("<H", b, 0x38)[0]):
        o = phoff + 56 * i
        if struct.unpack_from("<I", b, o)[0] == 1 and struct.unpack_from("<I", b, o + 4)[0] == 5:
            struct.pack_into("<I", b, o + 4, 7)
            break
    return bytes(b)


def test_f1_minor():
    """Issue 10: a framework call named like an app export; a library the engine refuses that holds the call's name
    or a JNI_OnLoad; liblog's model."""
    x = 0x10
    want = "ANS-%016X" % (x * 7 + 5)
    codec_valueof = ("Lcom/huntress/kb2/Codec;", "valueOf", "J", ["J"], 0x109, False)
    for decl in ((NAT_MIXJ,), (NAT_MIXJ, codec_valueof)):
        files = members(apk(chain_dex2(_emit_long("mix", x), list(decl)), {"lib/x86_64/libv.so": f1("valueof")}))
        check("M/10: Long.valueOf beside an app export Java_..._Codec_valueOf (declared native: %s): run as the "
              "framework's -> the judged key's code (review: no code, the decoy PLAIN end to end)" % (len(decl) > 1),
              judged_or_unsure(dcc.answer(Q, files), want), repr(dcc.answer(Q, files)))
    triv, w28 = r3("triv"), "ANS-%016X" % 28
    dinc = chain_dex2(_emit_long("inc", 5), [NAT_INC])
    big = _relr_bomb(triv, 4)                   # a device loads it; this engine refuses it (past its relocation cap)
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/x86_64/libbig.so": big}))
    o = opts_of(dcc.answer(Q, files))
    check("M/10: a copy past the engine's relocation cap (a device loads it) that also exports the name: its body "
          "read by the legacy reader alone, demoted +lib-unverified (its export address is not checked)",
          declines(ni.load, big) and
          o == ("mobile.codec/analysis+lib-unverified", [("analysis:dex-chain+lib-unverified", w28)]), repr(o))
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/x86_64/libbig.so": _relr_bomb(f1("helper"), 4)}))
    o = opts_of(dcc.answer(Q, files))
    check("M/10: such a library with a JNI_OnLoad (what it registers unknown) -> no code (so-ambig: a JNI_OnLoad not "
          "proven inert; the bridge alone demoted it +onload-unverified@unloadable)" + PORT, o is None, repr(o))
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/x86_64/libwx.so": _wx(triv),
                               "lib/x86_64/libwxh.so": _wx(f1("helper"))}))
    o = opts_of(dcc.answer(Q, files))
    check("M/10: a W+X copy and a W+X JNI_OnLoad library (refused here; Android before 8.0 loads them) -> no code "
          "(so-ambig: not loadable, and a JNI_OnLoad not proven inert; the bridge alone demoted it "
          "+onload-unverified@unloadable+lib-unverified)" + PORT, declines(ni.load, _wx(triv)) and o is None, repr(o))
    nophdr = bytearray(triv)
    struct.pack_into("<H", nophdr, 0x38, 0)                # e_phnum 0: no loader accepts it
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": bytes(nophdr)}))
    check("M/10: a library with no program headers (a fixture's shortcut; no loader accepts it): the legacy reader "
          "reads it as before this build -> the judged key's code", declines(ni.load, bytes(nophdr)) and
          judged_or_unsure(dcc.answer(Q, files), w28), repr(dcc.answer(Q, files)))
    big_helper = f1("helper") + bytes(nib.MAX_IMAGE_BYTES)  # a library past the size bound with a JNI_OnLoad
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/x86_64/libengine.so": big_helper}))
    loads = []
    o_load = nib._ni.load

    def c_load(b, *a, **kw):
        loads.append(len(b))
        return o_load(b, *a, **kw)
    nib.clear_caches()
    nib._ni.load = c_load
    try:
        o = opts_of(dcc.answer(Q, files))
    finally:
        nib._ni.load = o_load
    check("M/4: a library past the size bound that could bind the call only through its JNI_OnLoad -> no code "
          "(so-ambig: a JNI_OnLoad not proven inert; the bridge alone demoted it +onload-unverified@size), and the "
          "bridge never parses it (since fix round 3 so-ambig's decline comes first: nothing is parsed)" + PORT,
          o is None and loads in ([], [len(triv)]) and len(big_helper) not in loads, "%r %r" % (o, loads))
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/x86_64/libseek.so": f1("seekvm")}))
    o = opts_of(dcc.answer(Q, files))
    # since the port onto so-ambig: the constructor library's static f1_inc shares the binding key `_inc` with the
    # export (so-ambig's round 1 marks it EM_AMBIGUOUS across two bodies), and its DT_INIT_ARRAY is so-ambig's
    # constructor rule: no code where the bridge alone gave +onload-unverified@import-jni_getcreatedjavavms
    check("M/10: a library with no JNI_OnLoad whose constructor reaches the JavaVM (JNI_GetCreatedJavaVMs) and could "
          "register the native: no code (so-ambig: a second body defines the binding key; the bridge alone demoted "
          "it +onload-unverified@import-jni_getcreatedjavavms)" + PORT, dcc.answer(Q, files) is None, repr(o))
    fake32 = b"\x7fELF\x01\x01\x01" + b"\x00" * 57 + b"\x00JNI_OnLoad\x00"
    files = members(apk(dinc, {"lib/x86_64/libtriv.so": triv, "lib/armeabi-v7a/libhelper.so": fake32}))
    o = opts_of(dcc.answer(Q, files))
    check("M/10: a 32-bit library with a JNI_OnLoad (a device of that ABI runs it) -> +abi-unverified",
          o == ("mobile.codec/analysis+abi-unverified", [("analysis:dex-chain+abi-unverified", w28)]), repr(o))
    lr = f1("logret")
    check("M/liblog: a native whose result depends on __android_log_print's result declines (1 in one layout, -1 in "
          "the other); a NULL format declines; a NULL tag is the default tag -> its value",
          declines(ni.call_jni, lr, P + "logged", [("J", 5)], "J") and
          declines(ni.call_jni, lr, P + "lognull", [("J", 5)], "J") and
          ni.call_jni(lr, P + "logok", [("J", 5)], "J").value == 8)


def _relr_model(words):
    out, where = [], 0
    for e in words:
        if not e & 1:
            out.append(e)
            where = e + 8
        else:
            for b in range(63):
                if (e >> 1) >> b & 1:
                    out.append(where + 8 * b)
            where += 8 * 63
    return out


def _relr_bomb(so, mib):
    """`so` with a DT_RELR table of `mib` MiB of bitmap words that name no relocation, appended to its last writable
    PT_LOAD (DT_SONAME becomes DT_RELR, DT_SYMENT DT_RELRSZ)."""
    b = bytearray(so)
    phoff, phnum = struct.unpack_from("<Q", b, 0x20)[0], struct.unpack_from("<H", b, 0x38)[0]
    ph = [(phoff + 56 * i,) + struct.unpack_from("<IIQQQQQQ", b, phoff + 56 * i) for i in range(phnum)]
    ho, _t, _fl, off, va, _pa, fs, ms, _al = [p for p in ph if p[1] == 1 and p[2] & 2][-1]
    dyn = [p for p in ph if p[1] == 2][0]
    while len(b) % 16:
        b.append(0)
    start = len(b)
    n = (mib << 20) // 8
    b += struct.pack("<Q", 1) * n
    struct.pack_into("<QQ", b, ho + 32, len(b) - off, max(len(b) - off, ms))
    table = va + (start - off)
    for k in range(dyn[6] // 16):
        o = dyn[3] + 16 * k
        tag = struct.unpack_from("<q", b, o)[0]
        if tag == 14:
            struct.pack_into("<qQ", b, o, 36, table)
        elif tag == 11:
            struct.pack_into("<qQ", b, o, 35, 8 * n)
        elif tag == 0:
            break
    return bytes(b)


class _Stub:
    def __init__(self, raw):
        self.raw, self.R, self.relocs = raw, ni._X86, []

    def file_bytes(self, a, n):
        return self.raw[a:a + n]


def test_f1_costs():
    """Issues 4, 5, 6 and the process caches: libraries no call binds are never parsed or run; a RELR table is
    bounded; the bridge never parses a large secondary dex whole; each dex is read once a delivery; a warm process
    answers and charges what a cold one does."""
    triv, w28 = r3("triv"), "ANS-%016X" % 28
    dinc = chain_dex2(_emit_long("inc", 5), [NAT_INC])
    other = fx("kb2_jni_x86_64.so").replace(b"Java_com_huntress_kb2_NativeLab_", b"Java_com_huntress_kb2_NativeLbb_")
    libs = {"lib/x86_64/libtriv.so": triv}
    for k in range(24):
        libs["lib/x86_64/libother%d.so" % k] = other + bytes(k + 1)          # 24 unrelated libraries
    for k in range(12):
        libs["lib/x86_64/libspin%d.so" % k] = f1("spin") + bytes(k + 1)     # 12 whose constructors spin forever
    files = members(apk(dinc, libs))
    nib.clear_caches()
    loads, infos = [], []
    o_load, o_info = nib._ni.load, nib._ni.load_info

    def c_load(b, *a, **k):
        loads.append(len(b))
        return o_load(b, *a, **k)

    def c_info(*a, **k):
        infos.append(1)
        return o_info(*a, **k)
    nib._ni.load, nib._ni.load_info = c_load, c_info
    try:
        t = time.perf_counter()
        ans = dcc.answer(Q, files)
        dt = time.perf_counter() - t
    finally:
        nib._ni.load, nib._ni.load_info = o_load, o_info
    # since the port onto so-ambig: a library with DT_INIT_ARRAY anywhere in the delivery makes so-ambig decline every
    # binding (SO_CTORS), so the reading stands only demoted, +load-modelled@ctor; the bridge's costs are as before
    check("M/4: 36 libraries no call binds (24 unrelated, 12 spinning constructors) beside the binding one: only the "
          "binding library is parsed, no load phase runs, and no code (so-ambig's constructor rule: a library of the "
          "delivery has DT_INIT_ARRAY) (%.0f ms; review: 3.2-7.3 s a set)" % (1000 * dt) + PORT,
          ans is None and len(loads) <= 1 and not infos and dt < 1.5, "%r loads=%d infos=%d" % (ans, len(loads), len(infos)))
    libs = {"lib/x86_64/libtriv%d.so" % k: triv + bytes(k) for k in range(9)}
    files = members(apk(dinc, libs))
    t = time.perf_counter()
    ans = dcc.answer(Q, files)
    dt = time.perf_counter() - t
    check("M/4: nine libraries that all bind the call agree -> the judged key's code (%.0f ms)" % (1000 * dt),
          judged_or_unsure(ans, w28) and dt < 1.5, repr(ans))
    # RELR
    rnd = random.Random(27)
    words = []
    for _ in range(400):
        words.append(rnd.randrange(0, 1 << 30) * 8 if rnd.random() < 0.3 else (rnd.getrandbits(63) << 1) | 1)
    raw = b"".join(struct.pack("<Q", w) for w in words)
    stub = _Stub(raw)
    ni.ElfImage._read_relr(stub, 0, len(raw))
    check("M/5: the RELR reader produces exactly the relocations of an independent expansion (set bits only, in "
          "order)", [r[0] for r in stub.relocs] == _relr_model(words) and all(r[1] == ni._X86["REL"] for r in stub.relocs))
    t = time.perf_counter()
    refused = declines(ni.load, _relr_bomb(triv, 4))
    t_big = time.perf_counter() - t
    t = time.perf_counter()
    small = ni.load(_relr_bomb(triv, 1))
    t_small = time.perf_counter() - t
    check("M/5: a 4 MiB table of empty bitmap words is refused before it is walked (%.0f ms); a 1 MiB one loads "
          "(%.0f ms) with no relocation more than the library's own (review: 0.13 s per MiB)" % (1000 * t_big,
                                                                                            1000 * t_small),
          refused and t_big < 0.1 and t_small < 0.5 and len(small.relocs) == len(ni.load(triv).relocs))
    # a large secondary dex: the bridge reads its class headers, never its code items
    big = NDex()
    for c in range(300):
        cls = "Lcom/big/C%d;" % c
        for m in range(10):
            big.define(cls, big.m(cls, "m%d" % m, "V", []), 0x9, [0x0E], 1, 0, 0)
    big_dex = big.build()
    h_big = hashlib.sha256(big_dex).digest()
    blob = apk(dinc, {"lib/x86_64/libtriv.so": triv})
    parts = members(blob)
    parts["classes2.dex"] = big_dex
    seen = []
    o_init = dcc.Dex.__init__

    def c_init(self, data):
        seen.append(hashlib.sha256(bytes(data)).digest())
        o_init(self, data)
    nib.clear_caches()
    dcc.Dex.__init__ = c_init
    try:
        ans = dcc.answer(Q, dict(parts, **{"d.apk -> classes2.dex": big_dex, "d.apk -> classes.dex": parts["classes.dex"]}))
    finally:
        dcc.Dex.__init__ = o_init
    check("M/6: a 3,000-method classes2.dex listed twice: parsed once by the dex chain, never by the bridge (a view of "
          "its headers) -> the judged key's code (review: parsed whole for every bundle)",
          judged_or_unsure(ans, w28) and seen.count(h_big) == 1 and h_big in nib._VIEWS, "%r %d" % (ans, seen.count(h_big)))
    calls = []
    o_codes = dcc.codes_in_dex_ex

    def c_codes(data, *a, **k):
        # (since the port onto so-ambig, analysis_codes_ex hands codes_in_dex_ex a parsed Dex: its bytes are .d)
        calls.append(hashlib.sha256(bytes(data.d if isinstance(data, dcc.Dex) else data)).digest())
        return o_codes(data, *a, **k)
    dcc.codes_in_dex_ex = c_codes
    try:
        got = dcc.analysis_codes_ex(runner_files(blob))
    finally:
        dcc.codes_in_dex_ex = o_codes
    check("M/6: the runner's files (each dex twice): each dex member is run once, the same codes",
          len(calls) == len(set(calls)) == 1 and got == (["ANS-%016X" % 28], 0), "%r %r" % (calls, got))
    # caches: cold and warm give one answer, and a cached evaluation is charged to the budget like a computed one
    span = ni.load(fx("kb2_jni_x86_64.so")).hi - ni.load(fx("kb2_jni_x86_64.so")).lo

    def emit_two(a, d, mids):
        a.const_string(2, d.s("one"))
        a.invoke(0x71, mids["mixString"], [2])
        a.move_result_wide(0)
        a.const_string(3, d.s("two"))
        a.invoke(0x71, mids["mixString"], [3])
        a.move_result_wide(4)
        a.binop(0xA2, 0, 0, 4)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_two, [NAT_MIX]), {"lib/x86_64/libkb2.so": fx("kb2_jni_x86_64.so")}))
    saved = nib.TOTAL_SETUP_BYTES
    try:
        nib.clear_caches()
        nib.TOTAL_SETUP_BYTES = 4 * span
        warm = [dcc.answer(Q, files), dcc.answer(Q, files)]   # every evaluation of the delivery now cached
        nib.TOTAL_SETUP_BYTES = 2 * span                       # room for ONE evaluation
        one_warm = dcc.answer(Q, files)
        nib.clear_caches()
        one_cold = dcc.answer(Q, files)
    finally:
        nib.TOTAL_SETUP_BYTES = saved
    want = "ANS-%016X" % (m_mix_string("one") ^ m_mix_string("two"))
    check("M/caches: a warm process answers what a cold one answers, and a cached evaluation is charged to the "
          "delivery's budget of image bytes as a computed one (room for one evaluation: no code, warm or cold)",
          opts_of(warm[0]) == opts_of(warm[1]) == (IMG_KEY[0], [(IMG_KEY[1], want)]) and one_warm is None and
          one_cold is None, "%r %r %r" % (warm, one_warm, one_cold))


# ============================================================================== H. timing
# ============================================================================== N. fix round 2 (the review of 4250749)
def f2(name):
    return fx("kb2_f2_%s_x86_64.so" % name)


NAT_PROBE = [(LAB, n, "J", ["J"], 0x109, False) for n in ("step", "probe", "envchk", "burn")]


def emit_seq(seq, start):
    """C.run(): x = start; for fn in seq: x = fn(x); format(x)."""
    def emit(a, d, mids):
        a.const_wide(0, start)
        for fn in seq:
            a.invoke(0x71, mids[fn], [0, 1])
            a.move_result_wide(0)
        tail_format(a, d, 0)
    return emit


def burn_model(x):
    h = x & M64
    for _ in range(11000):
        h = (h * 6364136223846793005 + 1442695040888963407) & M64
    return h


def seq_value(seq, start, legacy=False):
    """The device's code of a probe-library chain (legacy=True: the shipped readers' emulator leg)."""
    x = start
    for fn in seq:
        if fn == "step":
            x = (x + 1) & M64
        elif fn == "burn":
            x = burn_model(x)
        elif fn == "probe":
            x ^= 0x1111 if legacy else 0x2222
        elif fn == "envchk":
            x ^= 0x4444
    return "ANS-%016X" % x


def never_plain_wrong(ans, truth):
    """True when `ans` is None, unsure, or exactly the device's code `truth`."""
    return ans is None or labels.is_unsure(ans) or ans == truth


@_needs_specimens
def test_f2_review1():
    """The review of 4250749: (a) a negative native return used as an index, (b) the image not asked (delivery caps,
    the size bound, an image problem, the work totals overspent), (c) a demotion dropped by an agreeing entry, the minor
    long-name item and the perf item; each a regression check of fix round 2."""
    probe = f2("probe")
    lib = {"lib/x86_64/libprobe.so": probe}
    # (b) 16 calls reach the evaluation cap; the 17th, an emulator check, was the legacy engine's leg PLAIN
    for seq, key in ((["step"] * 16 + ["probe"], "probe"), (["step"] * 16 + ["envchk"], "envchk")):
        files = members(apk(chain_dex(emit_seq(seq, 1), NAT_PROBE), lib))
        ans = dcc.answer(Q, files)
        o = opts_of(ans)
        check("N/b: past the delivery's 16-evaluation cap the shipped readers' reading of %s is demoted "
              "+image-unchecked@%s, never plain (review: PLAIN %s against the device's %s)"
              % (key, key, seq_value(seq, 1, True), seq_value(seq, 1)),
              o is not None and o[0] == "mobile.codec/analysis+image-unchecked@" + key, repr(ans))
    # (b) two calls of ~11,000 blocks a run: both runs of a call share what the totals left (no overspend)
    seq = ["burn", "burn", "probe"]
    files = members(apk(chain_dex(emit_seq(seq, 5), NAT_PROBE), {"lib/x86_64/libburn.so": f2("burn")}))
    ans = dcc.answer(Q, files)
    e1, _last, partial = solve_e2e(apk(chain_dex(emit_seq(seq, 5), NAT_PROBE), {"lib/x86_64/libburn.so": f2("burn")}))
    check("N/b: two heavy calls then an emulator check: never plain (review: the third call went unchecked and PLAIN %s, "
          "the device %s)" % (seq_value(seq, 5, True), seq_value(seq, 5)),
          unsure_or_none(ans) and unsure_or_none(e1) and _never_plain_but(partial, None), "%r %r" % (ans, e1))
    usage = {}
    try:
        ni.call_jni(f2("burn"), P + "burn", [("J", 5)], "J", max_blocks=nib.PER_RUN_BLOCKS, max_mem=nib.PER_RUN_MEM,
                    usage=usage, total_blocks=15000, total_mem=nib.TOTAL_MEM)
        got = "value"
    except ni.BudgetError:
        got = "budget"
    check("N/b: call_jni's total budget bounds BOTH runs together: a call that needs ~11,000 blocks a run stops at a "
          "total of 15,000 (BudgetError) and is charged at most 15,000 (%s, %r)" % (got, usage),
          got == "budget" and usage.get("blocks", 0) <= 15000, usage)
    # (b) the size bound: 9 MiB of zeros appended after the segments (no loader maps them)
    files = members(apk(chain_dex(emit_seq(["probe"], 5), NAT_PROBE), {"lib/x86_64/libprobe.so": probe + bytes(9 << 20)}))
    o = opts_of(dcc.answer(Q, files))
    check("N/b: a library padded past the size bound: the shipped readers' reading only demoted +image-unchecked@probe "
          "(review: PLAIN %s)" % seq_value(["probe"], 5, True),
          o is not None and o[0] == "mobile.codec/analysis+image-unchecked@probe", repr(o))
    # (b) an image problem the shipped readers do not see (Android APS2 packed relocations)
    aps2 = _patch_dyn_tag(probe, 0x6FFFFFF9, 0x60000011)
    files = members(apk(chain_dex(emit_seq(["probe"], 5), NAT_PROBE), {"lib/x86_64/libprobe.so": aps2}))
    o = opts_of(dcc.answer(Q, files))
    check("N/b: an image problem (APS2 relocations) the whole image refuses: the reading only demoted "
          "+image-unchecked@probe (review: DT_TEXTREL kept it PLAIN)", ni.load(aps2).problem and o is not None and
          o[0] == "mobile.codec/analysis+image-unchecked@probe", repr(o))
    files = members(apk(chain_dex(emit_seq(["step"], 5), NAT_PROBE), lib))
    check("N/b: control: one honest call -> the judged key's code (nothing over-declined)",
          judged_or_unsure(dcc.answer(Q, files), "ANS-%016X" % 6), repr(dcc.answer(Q, files)))
    # (a) a jint native returning -1 / -2 used as an array index (Java throws ArrayIndexOutOfBoundsException)
    neg = {"lib/x86_64/libneg.so": f1("negint")}
    for x, want in ((199, None), (198, None), (201, "ANS-%016X" % 0x22)):
        def emit(a, d, mids, x=x):
            a.const_wide(0, x)
            a.invoke(0x71, mids["sign"], [0, 1])
            a.move_result(2)
            a.const4(3, 4)
            a.new_array(4, 3, d.t("[I"))
            for k, val in enumerate((0x11, 0x22, 0x33, 0x44)):
                a.const4(5, k)
                a.const16(6, val)
                a.aput(0x4b, 6, 4, 5)
            a.aget(0x44, 7, 4, 2)
            a.unop(0x81, 0, 7)
            tail_format(a, d, 0)
        files = members(apk(chain_dex(emit, [(LAB, "sign", "I", ["J"], 0x109, False)]), neg))
        ans = dcc.answer(Q, files)
        check("N/a: sign(%d) = %d used as an int[4] index -> %s (review: PLAIN ...0044 / ...0033 from Python's negative "
              "indexing)" % (x, (x & 0xFF) - 200, "no code" if want is None else want),
              ans is None if want is None else judged_or_unsure(ans, want), repr(ans))

    def emit_negsize(a, d, mids):
        a.const_wide(0, 199)
        a.invoke(0x71, mids["sign"], [0, 1])
        a.move_result(2)
        a.new_array(4, 2, d.t("[I"))                 # new int[-1]: NegativeArraySizeException
        a.u.append(0x21 | (5 << 8) | (4 << 12))      # array-length v5, v4
        a.unop(0x81, 0, 5)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_negsize, [(LAB, "sign", "I", ["J"], 0x109, False)]), neg))
    check("N/a: a negative native return as a new-array size -> no code (it allocated 2^31 elements)",
          dcc.answer(Q, files) is None, repr(dcc.answer(Q, files)))
    # (c) a demotion is never dropped because another run gave the same code
    nib.reset()

    class _V:
        pass
    flagged, clean = _V(), _V()
    flagged._kb2_flags = frozenset({nib.FLAG_ONLOAD + "@jni-newglobalref"})
    clean._kb2_flags = frozenset()
    nib.note(flagged, "ANS-0000000000000075")
    nib.note(clean, "ANS-0000000000000075")
    check("N/c: image_suffix keeps a flagged run's demotion when an unflagged run gives the same code",
          nib.image_suffix(["ANS-0000000000000075"]) == "+onload-unverified@jni-newglobalref",
          nib.image_suffix(["ANS-0000000000000075"]))
    nib.reset()
    d = NDex()
    mid = d.m(LAB, "mix", "J", ["J"])
    d.define(LAB, mid, 0x109)
    a = Asm()
    a.const_wide(0, 0x10)
    a.invoke(0x71, mid, [0, 1])
    a.move_result_wide(0)
    tail_format(a, d, 0)
    d.define("Lcom/huntress/kb2/C;", d.m("Lcom/huntress/kb2/C;", "run", STRING, []), 0x9, a.finish(), 24, 0, 6)
    b = Asm()
    b.const_wide(0, 0x75)
    tail_format(b, d, 0)
    d.define("Lcom/huntress/kb2/D;", d.m("Lcom/huntress/kb2/D;", "run2", STRING, []), 0x9, b.finish(), 24, 0, 6)
    blob = apk(d.build(), {"lib/x86_64/libreg.so": f2("reghide")})
    ans = dcc.answer(Q, members(blob))
    e1, _last, partial = solve_e2e(blob)
    check("N/c: the export's reading beside a JNI_OnLoad that registers mix elsewhere, and a pure-Java entry giving the "
          "same code: never plain (review: PLAIN ...0075; a device's entries give ...0075 and ...00B7)",
          unsure_or_none(ans) and unsure_or_none(e1) and _never_plain_but(partial, None), "%r %r" % (ans, e1))
    # the minor item: overloaded natives exported under their LONG names, of a class named like ...Long
    hl = "Lcom/huntress/kb2/HexLong;"
    for libb, want in ((f2("hexlong"), "ANS-DEADBEEFCAFEBABE"), (f2("hexlong") + bytes(9 << 20), None)):
        d = NDex()
        mids = []
        for params in (["J"], ["I"]):
            mi = d.m(hl, "toHexString", STRING, params)
            d.define(hl, mi, 0x109)
            mids.append(mi)
        up = d.m(STRING, "toUpperCase", STRING, [])
        cc = d.m(STRING, "concat", STRING, [STRING])
        a = Asm()
        a.const_wide(0, 0x1122334455667788)
        a.invoke(0x71, mids[0], [0, 1])
        a.move_result_object(2)
        a.invoke(0x6E, up, [2])
        a.move_result_object(2)
        a.const_string(3, d.s("ANS-"))
        a.invoke(0x6E, cc, [3, 2])
        a.move_result_object(4)
        a.return_object(4)
        d.define("Lcom/huntress/kb2/C;", d.m("Lcom/huntress/kb2/C;", "run", STRING, []), 0x9, a.finish(), 24, 0, 6)
        ans = dcc.answer(Q, members(apk(d.build(), {"lib/x86_64/libhex.so": libb})))
        check("N/minor: an overloaded jstring native under its long name (%s): %s; never Long.toHexString's model "
              "(review: PLAIN ANS-1122334455667788 past the size bound)" % ("normal" if want else "padded past the size "
                                                                          "bound", want and "unsure +native-image" or
                                                                          "no code"),
              (opts_of(ans) == (IMG_KEY[0], [(IMG_KEY[1], want)])) if want else ans is None, repr(ans))
    d = NDex()
    folds = []
    for params in (["J"], ["I"]):
        mi = d.m(hl, "fold", "J", params)
        d.define(hl, mi, 0x109)
        folds.append(mi)
    a = Asm()
    a.const_wide(0, 7)
    a.invoke(0x71, folds[0], [0, 1])
    a.move_result_wide(0)
    tail_format(a, d, 0)
    d.define("Lcom/huntress/kb2/C;", d.m("Lcom/huntress/kb2/C;", "run", STRING, []), 0x9, a.finish(), 24, 0, 6)
    o = opts_of(dcc.answer(Q, members(apk(d.build(), {"lib/x86_64/libhex.so": f2("hexlong")}))))
    check("N/minor: an overloaded jlong native under its long name: the shipped reader reads the body under the short "
          "name, both engines agree, unsure under +jni-long (so-ambig binds no symbol of it)",
          o == ("mobile.codec/analysis+jni-long", [("analysis:dex-chain+jni-long", "ANS-%016X" % (7 * 3 + 4))]), repr(o))
    two = members(apk(d.build(), {"lib/x86_64/libhex.so": f2("hexlong"), "lib/x86_64/libhex2.so": f2("hexlong2")}))
    same = members(apk(d.build(), {"lib/x86_64/libhex.so": f2("hexlong"),
                                   "lib/x86_64/libhexcopy.so": f2("hexlong") + bytes(3)}))
    o_same = opts_of(dcc.answer(Q, same))
    check("N/merge: two libraries of one machine export the long name with other bytes (they compute alike): no code "
          "(x17's principle, which so-ambig's binding key cannot see for a long name); one body in two libraries: one "
          "definition, unsure +jni-long", dcc.answer(Q, two) is None and o_same == o, "%r %r" % (dcc.answer(Q, two), o_same))
    # perf: load phases charged to the delivery's image-bytes budget; a run writes only the non-zero ranges
    libs = {"lib/x86_64/libprobe.so": probe}
    for k in range(8):
        libs["lib/x86_64/libbig%d.so" % k] = f2("bigbss") + bytes(k + 1)
    files = members(apk(chain_dex(emit_seq(["step"], 5), NAT_PROBE), libs))
    nib.clear_caches()
    infos = []
    o_info = nib._ni.load_info

    def c_info(*a, **k):
        infos.append(1)
        return o_info(*a, **k)
    nib._ni.load_info = c_info
    try:
        t = time.perf_counter()
        ans = dcc.answer(Q, files)
        dt = time.perf_counter() - t
    finally:
        nib._ni.load_info = o_info
    big = ni.load(f2("bigbss"))
    st = ni._laid_out(big, 0)
    written = sum(e - s0 for s0, e in st["writes"])
    check("N/perf: eight JNI_OnLoad libraries with a 15 MiB .bss beside the binding one: the load phases are charged to "
          "the image-bytes budget (%d run, %.0f ms; review: 0.17 s), no code (so-ambig: a JNI_OnLoad not proven inert)"
          % (len(infos), 1000 * dt), len(infos) <= 1 and dt < 0.15 and ans is None, "%r %d %.3f" % (ans, len(infos), dt))
    check("N/perf: a run writes only the non-zero ranges of a laid-out image (%d bytes of a %d-byte span)"
          % (written, big.hi - big.lo), written < 64 << 10 < (big.hi - big.lo), written)


def _irelative(so):
    """`so` with its first RELA relocation's type made R_X86_64_IRELATIVE (37), or None when it has no RELA table."""
    img = ni.load(so)
    rela, relasz = img.dyn.get(7, [None])[0], img.dyn.get(8, [None])[0]
    if not rela or not relasz:
        return None
    off = next((o + rela - v for (v, m, fs, o, fl) in img.loads if v <= rela < v + fs), None)
    if off is None:
        return None
    b = bytearray(so)
    info = struct.unpack_from("<Q", b, off + 8)[0]
    struct.pack_into("<Q", b, off + 8, (info & ~0xFFFFFFFF) | 37)
    return bytes(b)


def test_f2_hardening():
    """The review's hardening notes 4 and 5 (none new on the tree before): an IRELATIVE resolver runs code at load time
    (now an image problem, so the image is never asked and a legacy reading only demoted); a classesN.dex after a gap in
    the numbering is no dex the app's class loader opens."""
    irel = _irelative(fx("kb2_jni_x86_64.so"))
    if irel is None:
        print("SKIP N/hardening IRELATIVE (the fixture has no RELA table)")
    else:
        img = ni.load(irel)
        check("N/hardening: an IRELATIVE relocation is an image problem (its resolver runs at load time)",
              img.problem is not None and "IRELATIVE" in img.problem and declines(ni.call_jni, irel, P + "mixString",
                                                                                  [("str", "a")], "J"), img.problem)
    nat = [(LAB, "inc", "J", ["J"], 0x109, False)]
    d1 = NDex()
    mid = d1.m(LAB, "inc", "J", ["J"])
    a = Asm()
    a.const_wide(0, 5)
    a.invoke(0x71, mid, [0, 1])
    a.move_result_wide(0)
    tail_format(a, d1, 0)
    d1.define("Lcom/huntress/kb2/C;", d1.m("Lcom/huntress/kb2/C;", "run", STRING, []), 0x9, a.finish(), 24, 0, 6)
    d2 = NDex()
    for (cls, name, ret, params, flags, virtual) in nat:
        d2.define(cls, d2.m(cls, name, ret, params), flags, virtual=virtual)
    triv = {"lib/x86_64/libtriv.so": r3("triv")}
    got = {}
    for second in ("classes2.dex", "classes3.dex"):
        files = members(apk(d1.build(), triv))
        files[second] = d2.build()
        got[second] = dcc.answer(Q, files)
    check("N/hardening: the native declared in classes2.dex binds (multidex; the judged key's code), in classes3.dex with "
          "no classes2.dex (a gap: ART never opens it) no code", judged_or_unsure(got["classes2.dex"], "ANS-%016X" % 28)
          and got["classes3.dex"] is None, repr(got))


def test_f2_vm_bounds():
    """Review item (a), the VM itself: every index checked as Java checks it."""
    j = dcc._jindex
    rows = [(lambda: j(2, 3, "t"), 2), (lambda: j(-1, 3, "t"), "decline"), (lambda: j(3, 3, "t"), "decline"),
            (lambda: j(3, 3, "t", end_ok=True), 3), (lambda: j(0xFFFFFFFF, 3, "t"), "decline"),
            (lambda: j(True, 3, "t"), "decline"), (lambda: j("1", 3, "t"), "decline")]
    got = []
    for fn, want in rows:
        try:
            got.append(fn())
        except dcc._Decline:
            got.append("decline")
    check("N/a: _jindex: in range, -1, n, n with end_ok, 0xFFFFFFFF (-1), a bool and a str", got == [w for _f, w in rows],
          got)
    vm = dcc.VM(None, {}, {})
    # fill-array-data: payload ident 0x0300, width 4, 3 elements into an int[2] (Java throws) and into an int[3]
    ins = [0x0026, 4, 0, 0x000e, 0x0300, 4, 3, 0, 1, 0, 2, 0, 3, 0]
    outs = []
    for arr in ([0, 0], [0, 0, 0]):
        try:
            vm.steps = 0
            vm._exec(ins, [arr])
            outs.append(arr)
        except dcc._Decline:
            outs.append("decline")
    check("N/a: fill-array-data of 3 elements: into an int[2] declines (it filled 2), into an int[3] fills it",
          outs == ["decline", [1, 2, 3]], outs)
    outs = []
    for lit in (0xF, 2):                              # const/4 v1, -1 / 2; new-array v0, v1, type@0; return-void
        try:
            vm.steps = 0
            R = [None, None]
            vm._exec([0x12 | (1 << 8) | (lit << 12), 0x23 | (0 << 8) | (1 << 12), 0, 0x000e], R)
            outs.append(R[0])
        except dcc._Decline:
            outs.append("decline")
    check("N/a: new-array of size -1 declines (NegativeArraySizeException), of size 2 allocates two zeros",
          outs == ["decline", [0, 0]], outs)


def test_f2_merge():
    """The port onto so-ambig: the merged native path answers plain only where so-ambig's binding rules and the bridge
    both allow it; RegisterNatives respects so-ambig's ambiguity rules (two bodies of one machine)."""
    nat_reg = [(LAB, "regOnly", "J", ["J"], 0x109, False)]
    dreg = chain_dex(_emit_long("regOnly", 5), nat_reg)
    o = opts_of(dcc.answer(Q, members(apk(dreg, {"lib/x86_64/liba.so": f2("rega")}))))
    check("N/merge: a native only a JNI_OnLoad registers (no symbol matches it): the registered function's code, image "
          "only, unsure (+native-image)", o == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % 16)]), repr(o))
    ans = dcc.answer(Q, members(apk(dreg, {"lib/x86_64/liba.so": f2("rega"), "lib/x86_64/libb.so": f2("regb")})))
    check("N/merge: two libraries of one machine each registering it (they agree): no code (so-ambig's two-bodies rule; "
          "the bridge alone answered)", ans is None, repr(ans))
    ans = dcc.answer(Q, members(apk(dreg, {"lib/x86_64/liba.so": f2("rega"), "lib/x86_64/libx.so": f2("regexp")})))
    check("N/merge: RegisterNatives in one library beside a second .so exporting its exact name with other code: no code",
          ans is None, repr(ans))
    evil = "Ljava/lang/Evil;"
    dboot = chain_dex(_emit_long("mix", 0x10), [(evil, "mix", "J", ["J"], 0x109, False)])
    ans = dcc.answer(Q, members(apk(dboot, {"lib/x86_64/libboot.so": f2("boot")})))
    check("N/merge: a native the dex declares in a java/ class, exported under its exact name: no code (a boot class is "
          "never one of the app's natives)", ans is None, repr(ans))

    def emit_ghost(a, d, mids):
        a.const_wide(0, 0x10)
        a.invoke(0x71, d.m("Lcom/huntress/kb2/Ghost;", "mix", "J", ["J"]), [0, 1])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    files = members(apk(chain_dex(emit_ghost, [NAT_INC]), {"lib/x86_64/libghost.so": f2("ghost")}))
    saved = dcc.native_image_bridge
    dcc.native_image_bridge = None
    try:
        alone = dcc.answer(Q, files)
    finally:
        dcc.native_image_bridge = saved
    ans = dcc.answer(Q, files)
    check("N/merge: a class no dex defines whose exact JNI name is exported: no code (the bridge runs it as a framework "
          "method, so-ambig binds the export: they disagree; so-ambig alone: %s)" % code_of(alone), ans is None,
          repr(ans))
    triv = {"lib/x86_64/libtriv.so": r3("triv")}
    ans = dcc.answer(Q, members(apk(chain_dex(_emit_long("inc", 5), [NAT_INC]), triv)))
    check("N/merge: control: one library, one exact export, no load-time code: the judged key's code (both rules bind)",
          judged_or_unsure(ans, "ANS-%016X" % 28), repr(ans))


# ============================================================================== O. fix round 3 (the review of 18ab31d)
def f3(name, abi="x86_64"):
    return fx("kb2_f3_%s_%s.so" % (name, abi))


def honest3(x):
    t = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3]
    for i in range(len(b"huntress")):
        x = ((x ^ t[(x + i) & 15]) * 0x100000001B3) & M64
    return x


def hchurn3(x):
    """kb2_f3_hchurn's value, computed here."""
    acc, buf = x & M64, []
    for i in range(40):
        buf.append(ord("a") + (acc + i) % 26)
        acc = (acc * 31 + buf[-1]) & M64
    for i, ch in enumerate(buf):
        acc ^= (ch << (i % 56)) & M64
    return acc


def offered(ans):
    """Every code an answer gives, plain or offered."""
    if ans is None:
        return []
    o = opts_of(ans)
    return [v for _n, v in o[1]] if o else [ans]


@_needs_specimens
def test_f3_review2():
    """The review of 18ab31d. (1) The two-layout check compared absolute addresses only: the JNIEnv's reserved0..3 and
    the JavaVM's reserved0..2 held trap addresses where ART has NULL, the traps sat 16 bytes apart in both layouts, as
    did malloc's red zone (16) and the local references (0x10), so an emulator check on any of them took its decoy leg in
    both runs: unsure under +native-image, and PLAIN after one acceptance of that key (af3dbf7: None). Now the reserved
    slots are NULL, only ART's slots are defined, and the trap stride and order, the reference step and the red zone
    differ per layout; beyond the review, so do the allocator's identity choices (a freed block handed back, a block
    realloc keeps), which a bump heap answered the same way in both runs. (2) +onload-unverified@<why> names only the
    first thing a JNI_OnLoad met: a decoy with the same
    first import that then registers another function shared the key. Where so-ambig binds no symbol, such a reading
    declines. (4) so-ambig's verdict comes before any library is parsed or any load phase runs."""
    nat = [(LAB, "mix", "J", ["J"], 0x109, False)]
    dmix = chain_dex(_emit_long("mix", 0x1000), nat)
    dev, decoy = "ANS-%016X" % (0x1000 ^ 0x2222), "ANS-%016X" % (0x1000 ^ 0x1111)
    x86, a64 = "lib/x86_64/libadv.so", "lib/arm64-v8a/libadv.so"
    # (1) reserved slots: the device's leg is read (image only, unsure), never the decoy
    for label, libs in (("x86_64", {x86: f3("res0")}), ("arm64", {a64: f3("res0", "arm64")}),
                        ("x86_64 + arm64", {x86: f3("res0"), a64: f3("res0", "arm64")})):
        files = members(apk(dmix, libs))
        ans = dcc.answer(Q, files)
        check("O/1: a native testing (*env)->reserved0 != NULL (%s): the device's leg (ART's reserved slots are NULL), "
              "image only, unsure; never the decoy (review: the decoy under +native-image, plain after one acceptance)"
              % label, opts_of(ans) == (IMG_KEY[0], [(IMG_KEY[1], dev)]) and decoy not in offered(ans), repr(ans))
    check("O/1: the engine itself: reserved0 reads NULL in both runs",
          ni.call_jni(f3("res0"), P + "mix", [("J", 0x1000)], "J").value == 0x1000 ^ 0x2222)
    # (1) distances that were the same in both layouts: they differ now, so a result that depends on one declines
    for name, what in (("stride", "the distance between two JNIEnv slots (16 x 165 in both layouts before)"),
                       ("libcptr", "the distance between two libc import stubs (16 in both layouts before)"),
                       ("heap", "the distance between two malloc(16) blocks (32 in both layouts before)")):
        files = members(apk(dmix, {x86: f3(name)}))
        ans = dcc.answer(Q, files)
        check("O/1: a native testing %s: no code, never the decoy (review: the decoy plain after one acceptance)"
              % what, ans is None and decoy not in offered(ans) and
              declines(ni.call_jni, f3(name), P + "mix", [("J", 0x1000)], "J"), repr(ans))
    files = members(apk(dmix, {x86: f3("stride"), a64: f3("stride", "arm64")}))
    check("O/1: the slot-distance check in an x86_64 + arm64 pair: no code", dcc.answer(Q, files) is None,
          repr(dcc.answer(Q, files)))
    nat2 = [(LAB, "mix2", "J", [STRING], 0x109, False)]
    files = members(apk(chain_dex(_emit_str_arg("mix2", "zz"), nat2), {x86: f3("handles")}))
    ans = dcc.answer(Q, files)
    check("O/1: a native testing the distance between two local references (0x10 in both layouts before): no code, "
          "never the decoy", ans is None and "ANS-%016X" % 0x1111 not in offered(ans), repr(ans))
    # (1) the JavaVM's reserved slots in a load phase: JNI_OnLoad registers the device's function
    for label, libs in (("x86_64", {x86: f3("vmres")}), ("arm64", {a64: f3("vmres", "arm64")})):
        ans = dcc.answer(Q, members(apk(dmix, libs)))
        check("O/1: a JNI_OnLoad testing (*vm)->reserved0 before RegisterNatives (%s): the device's function (image "
              "only, unsure), never the decoy" % label,
              opts_of(ans) == (IMG_KEY[0], [(IMG_KEY[1], dev)]) and decoy not in offered(ans), repr(ans))
    ans = dcc.answer(Q, members(apk(dmix, {x86: f3("honest")})))
    check("O/1: control: an honest native that needs the whole image (PLT strlen, a .rodata table): its code, image "
          "only, unsure", opts_of(ans) == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % honest3(0x1000))]), repr(ans))
    # (2) two JNI_OnLoads with the same <why> tag (+onload-unverified@import-getpid), the method exported by its long
    # name only (so-ambig binds no symbol of it): both decline; the decoy's export code is never given
    for name, export_code in (("olhonest", "ANS-%016X" % (0x1000 * 7 + 5)), ("oldecoy", decoy)):
        files = members(apk(dmix, {x86: f3(name)}))
        ans = dcc.answer(Q, files)
        e1, _last, partial = solve_e2e(apk(dmix, {x86: f3(name)}))
        check("O/2: a JNI_OnLoad that meets getpid first (%s) beside a long-name export: no code (its key "
              "+onload-unverified@import-getpid is the same for the donor and the decoy; review: the decoy's export "
              "plain after one acceptance)" % name, ans is None and export_code not in offered(ans) and
              not plain_is(e1, decoy) and _never_plain_but(partial, None), "%r %r" % (ans, e1))
    # (4) eight libraries whose JNI_OnLoad spins beside an export whose call spins: so-ambig declines first, so no
    # library is parsed and no load phase runs
    libs = {"lib/x86_64/libburncall.so": f3("burncall")}
    for k in range(8):
        libs["lib/x86_64/libburnload%d.so" % k] = f3("burnload") + bytes(k + 1)
    files = members(apk(chain_dex(_emit_long("mix", 7), nat), libs))
    nib.clear_caches()
    infos, loads = [], []
    o_info, o_load = nib._ni.load_info, nib._ni.load

    def c_info(*a, **k):
        infos.append(1)
        return o_info(*a, **k)

    def c_load(*a, **k):
        loads.append(1)
        return o_load(*a, **k)
    nib._ni.load_info, nib._ni.load = c_info, c_load
    try:
        t = time.perf_counter()
        ans = dcc.answer(Q, files)
        dt = time.perf_counter() - t
    finally:
        nib._ni.load_info, nib._ni.load = o_info, o_load
    check("O/4: eight spinning JNI_OnLoads beside a spinning export: so-ambig's decline comes first, no library parsed, "
          "no load phase run (%.0f ms; review: 0.50 s a delivery cold)" % (1000 * dt),
          ans is None and not infos and not loads and dt < 0.15, "%r infos=%d loads=%d %.3f" % (ans, len(infos),
                                                                                              len(loads), dt))
    # (2) and item 3: a long-name binding (so-ambig binds no symbol of it) beside a 32-bit leg holding that name: what a
    # device of that ABI runs is unknown and nothing vouches for the binding, so it declines (alone: unsure +jni-long)
    hl = "Lcom/huntress/kb2/HexLong;"
    d = NDex()
    folds = []
    for params in (["J"], ["I"]):
        mi = d.m(hl, "fold", "J", params)
        d.define(hl, mi, 0x109)
        folds.append(mi)
    a = Asm()
    a.const_wide(0, 7)
    a.invoke(0x71, folds[0], [0, 1])
    a.move_result_wide(0)
    tail_format(a, d, 0)
    d.define("Lcom/huntress/kb2/C;", d.m("Lcom/huntress/kb2/C;", "run", STRING, []), 0x9, a.finish(), 24, 0, 6)
    leg32 = fx("kb2_r3_triv_armv7a.o") + b"Java_com_huntress_kb2_HexLong_fold__J\x00"
    alone = opts_of(dcc.answer(Q, members(apk(d.build(), {"lib/x86_64/libhex.so": f2("hexlong")}))))
    ans = dcc.answer(Q, members(apk(d.build(), {"lib/x86_64/libhex.so": f2("hexlong"),
                                                "lib/armeabi-v7a/libhex.so": leg32})))
    check("O/3: a long-name binding beside a 32-bit leg holding that name: no code (so-ambig binds no symbol of it, and "
          "the 32-bit device's binding is unknown); alone it is unsure +jni-long",
          ans is None and alone is not None and alone[0] == "mobile.codec/analysis+jni-long", "%r %r" % (ans, alone))
    # (1, beyond the review) the allocator's identity choices: run A never hands a freed block back and always moves a
    # block on realloc, run B reuses and resizes in place wherever a device's allocator might, so a result that depends
    # on either declines (before: both runs a bump heap, the decoy under +native-image, plain after one acceptance)
    for name, what in (("reuse", "free(a), then malloc of the same size: a == b"),
                       ("rshrink", "realloc to a smaller size keeps the block"),
                       ("rgrow", "realloc growth inside its size class keeps the block"),
                       ("rlast", "realloc growth of the last block keeps it")):
        files = members(apk(dmix, {x86: f3(name)}))
        ans = dcc.answer(Q, files)
        check("O/1: a native testing the allocator's identity (%s): no code, never the decoy (before: the decoy plain "
              "after one acceptance of +native-image)" % what, ans is None and decoy not in offered(ans) and
              declines(ni.call_jni, f3(name), P + "mix", [("J", 0x1000)], "J"), repr(ans))
    ans = dcc.answer(Q, members(apk(dmix, {x86: f3("reuse"), a64: f3("reuse", "arm64")})))
    check("O/1: the reuse check in an x86_64 + arm64 pair: no code", ans is None, repr(ans))
    for label, libs in (("x86_64", {x86: f3("hchurn")}), ("arm64", {a64: f3("hchurn", "arm64")})):
        ans = dcc.answer(Q, members(apk(dmix, libs)))
        check("O/1: control: an honest native that churns the heap (a buffer grown by realloc, a scratch block freed "
              "and asked for again; %s): its code, image only, unsure" % label,
              opts_of(ans) == (IMG_KEY[0], [(IMG_KEY[1], "ANS-%016X" % hchurn3(0x1000))]), repr(ans))
    check("O/1: the allocator rules: sizes one class on every Android allocator, sizes two classes on every one, the "
          "rest neither (run B declines a reuse there), and run B's room above any allocator's usable size",
          ni._heap_same(16, 16) and ni._heap_same(3, 8) and ni._heap_same(9, 16) and ni._heap_same(20, 32) and
          not ni._heap_same(8, 9) and not ni._heap_same(60, 70) and not ni._heap_same(250, 260) and
          ni._heap_apart(8, 64) and ni._heap_apart(16, 17) and not ni._heap_apart(17, 32) and
          not ni._heap_apart(250, 260) and ni._heap_apart(100, 265) and
          all(ni._heap_room(n) >= u for n, u in ((1, 16), (16, 16), (17, 32), (433, 576), (4609, 7104),
                                                  (33281, 65536))))
    # the layouts themselves: what a native could compare across the two runs differs
    A, B = ni._LAYOUTS
    check("O/1: the layouts differ in the trap stride and order, the reference step, the heap red zone and the "
          "allocator's identity choices",
          A["trap_step"] != B["trap_step"] and A["trap_rev"] != B["trap_rev"] and
          A["handle_step"] != B["handle_step"] and A["heap_gap"] != B["heap_gap"] and
          A["heap_classes"] != B["heap_classes"] and
          all(ni._trap_id(L, ni._layout_trap(L, k)) == k for L in (A, B) for k in (0, 1, 255, 256, 767)))


def _emit_str_arg(fn, text):
    """C.run(): mix2(text) as a long, then format."""
    def emit(a, d, mids):
        a.const_string(2, d.s(text))
        a.invoke(0x71, mids[fn], [2])
        a.move_result_wide(0)
        tail_format(a, d, 0)
    return emit


def test_timing():
    img = ni.load(fx("kb2_jni_x86_64.so"))
    ts = []
    for _ in range(5):
        t = time.perf_counter()
        ni.call_jni(img, P + "mixString", [("str", "timing probe")], "J")
        ts.append(time.perf_counter() - t)
    ts.sort()
    print("INFO per-call whole-image time (two runs): median %.1f ms, max %.1f ms" % (1000 * ts[2], 1000 * ts[-1]))
    check("H/a whole-image call stays well under the 1.5 s set cap", ts[2] < 0.25)


def main():
    cache_identity_checks()
    if not ni.UNICORN_AVAILABLE:
        print(f"SKIP emulation: unicorn engine not available; cache identity {PASS} passed, {FAIL} failed")
        return 1 if FAIL else 0
    t0 = time.perf_counter()
    test_engine_fixtures()
    test_engine_determinism()
    test_jni_layout()
    test_decoys()
    test_real_libraries()
    test_relocation_strictness()
    test_binary_api()
    test_dex_integration()
    test_legacy_unchanged()
    test_codec_search_end_to_end()
    test_load_phase_engine()
    test_load_phase_dex()
    test_environment()
    test_bridge_bounds()
    test_r3_binding()
    test_r3_state_and_layouts()
    test_r3_demotions()
    test_r3_budgets()
    test_f1_fallthrough()
    test_f1_demotions()
    test_f1_image_failed()
    test_f1_values()
    test_f1_minor()
    test_f1_costs()
    test_f2_review1()
    test_f2_vm_bounds()
    test_f2_merge()
    test_f2_hardening()
    test_f3_review2()
    test_timing()
    print("\n%d passed, %d failed (%.1f s)" % (PASS, FAIL, time.perf_counter() - t0))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
