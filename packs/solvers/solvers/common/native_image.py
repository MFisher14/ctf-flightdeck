#!/usr/bin/env python3
"""Whole-image, bounded, syscall-free emulation of an ELF shared object or executable (KB-2).

WHY THIS FILE EXISTS
--------------------
`native_emulate.py` runs ONE function with only that function's bytes mapped: a JNI transform that calls a
sibling function, goes through a PLT stub, reads a .rodata table or a .data pointer, or calls into libc or
back into the JNIEnv cannot run there (Mobile native transforms cost 26-27 minutes on Days 23 and 25). This
module loads the WHOLE image the way the dynamic loader does and runs a function in it:

  * every PT_LOAD segment is mapped at its vaddr (plus a load bias for ET_DYN), file-backed, the .bss tail
    zero-filled and DEFINED; bytes of a mapped page that no segment covers are UNDEFINED;
  * the deterministic dynamic relocations are applied (R_*_RELATIVE, and R_*_GLOB_DAT / R_*_JUMP_SLOT /
    R_X86_64_64 / R_AARCH64_ABS64 against a symbol DEFINED in the same image, or against a modelled libc
    function); every other relocation target is POISONED (undefined), so a read through an unrelocated
    pointer declines, and a call to an import this module does not model lands on a trap that declines;
  * a modelled libc subset reached through the PLT/GOT by import name (strlen, memcpy, memmove, memset,
    memcmp, strcmp, strncmp, strcpy, strncpy, strchr, malloc/calloc/realloc/free on a bounded deterministic
    bump heap, their bionic FORTIFY `__*_chk` forms), and liblog's __android_log_print/_write/_vprint (a log
    line: its tag and text are read as C strings, its result is 1 in one layout and -1 in the other);
    `__stack_chk_fail` declines; everything else declines;
  * a fake JNIEnv: the real JNI function-table slot layout (jni.h, JNINativeInterface): reserved0..3 NULL as in
    ART (and the JavaVM's reserved0..2), every other slot a trap address, nothing past ART's last slot; GetStringUTFChars, ReleaseStringUTFChars, GetStringUTFLength, GetStringLength, NewStringUTF,
    GetArrayLength, Get/ReleaseByteArrayElements, Get/SetByteArrayRegion, NewByteArray,
    Get/ReleaseIntArrayElements, ExceptionCheck (false), ExceptionOccurred (NULL), ExceptionClear, GetVersion
    (1.6), DeleteLocalRef, FindClass (only a class the caller lists: the delivery's own dex) and
    RegisterNatives (load phase only, only a method the caller lists as declared native) are modelled exactly
    (the model never has a pending exception: every throwing case declines); every other slot declines;
  * the LOAD PHASE before every call, as the loader and ART run it: DT_INIT, then every DT_INIT_ARRAY slot
    (an executable's DT_PREINIT_ARRAY first), then an exported JNI_OnLoad(JavaVM*, NULL) with a fake JavaVM
    (GetEnv, AttachCurrentThread[AsDaemon]) that must return a version ART accepts (1.2, 1.4, 1.6);
    load_info() reports what it registered (two layouts must agree; cached per image). A call starts from
    the loaded state; constructors that cannot be modelled make every call into the image decline;
  * a TLS block with only the stack-protector slot defined (x86-64 %fs:0x28, AArch64 TPIDR_EL0+0x28, as
    bionic and glibc place it), so code built with -fstack-protector runs, and a smashed canary declines;
  * machine-dependent instructions decline (native_emulate.X86_ENV_INSNS: rdtsc, cpuid, rdrand, xgetbv, ...;
    AArch64 MRS/MSR of anything but TPIDR_EL0/NZCV/FPCR/FPSR, SYS/SYSL): an emulator check reads them, and
    Unicorn answers them identically in both runs, so the double run alone cannot catch them.

NOTHING FROM THE SAMPLE IS EVER RUN ON THE HOST. Unicorn emulates it in its own memory: no host process,
no files, no network. Syscalls / software interrupts are trapped and declined.

NEVER-WRONG CONTRACT (the bright line; extends native_emulate's)
-----------------------------------------------------------------
A value is returned ONLY when the function returns to its caller deterministically within budget and its
result depends on nothing undefined. Anything else raises `EmulationError`:

  * Bounded by WORK, never by a clock: at most `max_blocks` translated blocks and `max_mem` memory accesses
    per run (so the base, the gate's replay and a clock agree). The work a modelled libc or JNI function does
    (bytes copied, set, compared, scanned) counts against `max_mem` too, one access per 64 bytes.
  * Byte-granular definedness on EVERY memory access: a read of a byte that no segment, relocation, model or
    store defined declines (unwritten stack, malloc'd-but-unwritten heap, freed heap, poisoned GOT slots,
    page gaps, TLS slots other than the canary).
  * Writes only where the process could write: RW segments outside RELRO (RELRO is read-only after the
    relocations, rounded up to whole pages as bionic does), the stack, live heap blocks, TLS. A write to code,
    .rodata, RELRO, freed or unallocated heap declines.
  * Two runs with DIFFERENT layouts and poison fills: image base, stack, heap, TLS, JNIEnv, trap and handle
    addresses all differ between the runs (the image base in every bit from 12 to 35, the stack top and the
    heap's blocks in every bit from 4 to 35, references in bits 2 to 11 and in ART's kind bits; _LAYOUTS), as do
    the poison in undefined/clobbered registers, the canary, the flags after a call, and every
    implementation-defined choice the model makes (the magnitude of a memcmp/strcmp result, the isCopy flag of
    Get<Prim>ArrayElements). The result (and every Java array the call commits) must be identical in both runs,
    so a result that depends on an address, a handle value, an uninitialised register, a clobbered register or
    an implementation-defined detail declines. Both layouts look like a device's (no "round" base), so an
    emulator check that tests for a fixed, aligned load address takes its device leg in both. Since KB-2 fix
    round 3 (the review of 18ab31d) DISTANCES and orders differ too, not only absolute addresses: the trap stride and
    order (16 bytes forward / 48 reversed: two JNI slots, two libc stubs), the step between references (0x10 / 0x30)
    and the heap's red zone between blocks (16 / 48), so a check of a distance an emulator keeps fixed declines. And
    the allocator's identity choices differ: run A never hands a freed block back and always moves a block on
    realloc; run B hands back the most recently freed block of the request's size class and resizes in place inside
    each block's room (twice its first request, at least 32 bytes: more than scudo or jemalloc keeps), declining a
    reuse that one Android allocator would make and another not. So `free(a); b = malloc(n); a == b` and
    `realloc(p, n) == p`, which a device's allocator answers its own way, decline.
  * A Java array has ONE elements buffer at a time: a second Get<Prim>ArrayElements of it, a SetByteArrayRegion
    while its buffer is held, or a GetByteArrayRegion while its buffer holds unreleased changes declines (a VM
    that pins the array and one that copies it give different answers there).
  * Integer arguments narrower than 64 bits carry poison in their upper 32 bits (the ABI leaves them
    unspecified), and so does an `int` return (only its low 32 bits are read).
  * State never escapes a call: a call that leaves any byte of the image's writable segments or of TLS changed
    (a counter, a lazily-built table) declines, the heap blocks the load phase allocated are read-only during a
    call and can never be freed, and the load phase's JNI local references are gone when it ends (ART frees
    them when JNI_OnLoad returns), so every call sees the loaded state and calls are order-free.
  * The function must return to the sentinel the caller pushed; falling off, a fetch outside the image's
    code (including page gaps), or a fetch from the stack/heap declines.
  * An image with something the loader would do that is not modelled (text relocations, a relocation outside a
    writable segment, a writable AND executable PT_LOAD, a PT_LOAD whose file
    offset and address are not congruent modulo the page, a GLOB_DAT / JUMP_SLOT with an addend, where bionic and
    glibc differ; since KB-2 fix round 2 an IRELATIVE relocation or a slot bound to an IFUNC, whose resolver runs at
    load time) declines as a whole or at that slot.
  * Work bounds shared by both runs (KB-2 fix round 2): call_jni / load_info take optional `total_blocks` /
    `total_mem`, and each run gets at most its per-run cap and what the run before it left. A run writes only the
    non-zero ranges of the laid-out image (file-backed bytes and relocation slots) into its fresh, zero-filled
    mapping, so a large .bss costs its shadow arrays and no copy.

B-241 (native emulation depth)
------------------------------
  * Android packed relocations (DT_ANDROID_RELA, the "APS2" SLEB128 groups lld writes with
    --pack-dyn-relocs=android) are decoded exactly as bionic's packed_reloc_iterator decodes them, into the same
    rows a DT_RELA table gives, and applied first, as bionic applies them. A bad header, a truncated stream or a
    DT_ANDROID_REL table (which a 64-bit bionic refuses) is an image problem: the whole image declines.
  * jfloat / jdouble JNI arguments and returns: the values travel in the vector registers (xmm0-7 / v0-7) with
    the bits above the value poisoned, as the ABI leaves them. A value is an IEEE bit pattern, compared bit for
    bit between the two runs; a NaN result declines (its sign and payload are the processor's), and so does an
    x86 instruction whose result a processor family chooses (rsqrtss, rcpss, the x87 transcendentals).
  * The JNI reference lifecycle: NewGlobalRef / DeleteGlobalRef, NewLocalRef, NewWeakGlobalRef /
    DeleteWeakGlobalRef, PushLocalFrame / PopLocalFrame, EnsureLocalCapacity, GetObjectRefType, IsSameObject,
    GetJavaVM and balanced MonitorEnter / MonitorExit. A global reference JNI_OnLoad creates lives on into every
    call (and may not be deleted by one); a weak reference is usable only through a promotion while something
    else holds its object; a frame capacity ART versions disagree on, a monitor still held at return and every
    throwing case decline.
  * Mach-O 64-bit images (x86-64, arm64) are mapped by macho_image.py into the same engine: load(data,
    macho=True) takes either container (emulate_symbol and the CLI pass it); without it a Mach-O file is an
    EmulationError, so an ELF-only caller (the Android bridge, the binary lane's reader) declines on one.

PUBLIC API
----------
    import native_image as ni
    ni.UNICORN_AVAILABLE, ni.EmulationError
    img = ni.load(elf_bytes)                 -> ElfImage (cached by content); raises EmulationError
    img = ni.load(data, arch, macho=True)    -> ElfImage or macho_image.MachOImage (a Mach-O file opts in)
    img.arch, img.exports(), img.ambiguous_exports(), img.symbol(name), img.problem, img.constructors(),
    img.has_load_code(jni)
    ni.emulate_symbol(elf_bytes, symbol_or_vaddr, args, arch=None, ret="int", init="auto") -> int | str
        plain C ABI (Binary lane): args are ints, or bytes/bytearray (copied to the heap and passed as a
        pointer; a bytearray is updated in place when both runs agree on its final content); ret="cstr"
        reads the returned pointer as a NUL-terminated UTF-8 string; init="auto" runs the constructors first,
        "skip" reads the pristine image.
    ni.emulate_call(elf_bytes, symbol_or_vaddr, args, init="auto", state="check", output="decline")
        a call rebuilt from a call site (B-166): args also take ni.ImagePtr(vaddr) (the image's own pointer)
        and ni.OutBuf(size) (an undefined output buffer, returned in the object); the result carries the
        return register (value / value32), the string at a returned pointer (cstr) and, with
        state="report", the image memory the call changed (changes); with output="capture", what it printed
        through puts / putchar / printf / write (stdout, stderr). Returns a CallResult.
    ni.call_jni(img, symbol, jargs, ret, static=True, classes=(), natives=(), entry=None, ...) -> JniResult
        the JNI entry (Mobile lane): jargs [(kind, value)], kinds Z B S C I J F D str arr:B arr:I arr:? obj;
        `entry` is a vaddr a RegisterNatives bound (from load_info) in place of the exported `symbol`.
    ni.load_info(img, classes=(), natives=()) -> {"load_code", "version", "registered": {(cls, name, sig): vaddr}}
"""
import hashlib
import os
import struct
import sys

if os.path.dirname(os.path.abspath(__file__)) not in sys.path:      # run as a script with -I
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import native_emulate as _ne  # noqa: E402

EmulationError = _ne.EmulationError


class SetupError(EmulationError):
    """The function was NOT run (KB-2 fix round 1): the engine, the image or an argument is something this model
    does not take (an image problem, a layout it cannot map, an argument kind or value it does not model, capstone
    or unicorn missing). It says nothing about what the code would do. A caller that holds another reading of the
    same function may keep it, as it did before this module existed."""


class BudgetError(EmulationError):
    """The function ran and was stopped by its WORK budget (blocks, memory accesses, work inside a modelled
    function) before it returned: no result, and no proof that it followed any particular path."""


UNICORN_AVAILABLE = _ne.UNICORN_AVAILABLE
ARCH_X86_64 = _ne.ARCH_X86_64
ARCH_ARM64 = _ne.ARCH_ARM64
_uc = _ne._uc
_x86c = _ne._x86c
_a64c = _ne._a64c

M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF
PAGE = 0x1000

EM_X86_64 = 62
EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3

MAX_ELF = 32 << 20             # an image larger than this is not emulated
MAX_SPAN = 64 << 20            # nor one whose PT_LOAD span is larger
MAX_RELOCS = 200_000
MAX_SYMS = 200_000
STACK_SIZE = 256 << 10
HEAP_SIZE = 1 << 20
MAX_STR = 1 << 16              # longest C string a model will scan
MAX_COPY = 1 << 20             # longest block a model will copy/set/compare
MAX_JARRAY = 1 << 20           # longest Java array NewByteArray may create

DEFAULT_MAX_BLOCKS = 50_000    # per run
DEFAULT_MAX_MEM = 200_000      # memory accesses per run

_POISON = (0xA5A5A5A5A5A5A5A5, 0x5C5C5C5C5C5C5C5C)

# Two layouts, one per run: every address the emulated code can observe differs between them, in every bit above
# the alignment a device guarantees (review of e71b954: bases that agreed on bits 12-27 let a load-bias check take
# its emulator leg in both runs). Image bases (ET_DYN, page-aligned): bits 12-35 complementary (0x51A5C3 /
# 0xAE5A3C), one base above 2^39 and one below it (arm64 devices with a 39-bit address space load below), and
# neither "round", so a check that an address looks like an emulator's fixed base sees device-like addresses in
# both runs. The stack top a call starts from and the first heap block: complementary in bits 4-35 (16-byte
# granularity). JNI references: bits 2-11 complementary, run B carrying ART's local-reference kind bits (01) and
# run A none. The JNIEnv, its function table, the JavaVM and the trap (function pointer) addresses sit at offsets
# that differ too.
_LAYOUTS = (
    dict(image=0x7F351A5C3000, stack=0x7FFC3A5C6000, stack_gap=0x5B0, heap=0x7A115C3A5000, heap_off=0xA50,
         tls=0x7B2200000000, jni=0x7C3300000000, env_off=0x5A8, vm_off=0xA58, vt_off=0x100, table_off=0x0A8,
         trap=0x7D4400000000, trap_off=0x5A0, handle=0x7E55000005A4, canary=0x2F9D1C3B5A7E8F00,
         flags_x86=0x8C3, nzcv=0xF0000000, cmp_scale=1, iscopy=1, log_ret=1,
         trap_step=16, trap_rev=False, handle_step=0x10, heap_gap=16, heap_classes=False, tls_off=0x5A0,
         puts_ret=None),
    dict(image=0x007AE5A3C000, stack=0x7FE3C5A3B000, stack_gap=0xA60, heap=0x612EA3C5A000, heap_off=0x5A0,
         tls=0x623400000000, jni=0x634500000000, env_off=0xA50, vm_off=0x5A0, vt_off=0xE00, table_off=0x850,
         trap=0x645600000000, trap_off=0xA50, handle=0x656700000A59, canary=0x51E0A7C3964DB200,
         flags_x86=0x006, nzcv=0x00000000, cmp_scale=0x101, iscopy=0, log_ret=-1,
         trap_step=48, trap_rev=True, handle_step=0x30, heap_gap=48, heap_classes=True, tls_off=0xA40,
         puts_ret=0),
)

# KB-2 fix round 3, beyond the review of 18ab31d: whether a freed block comes straight back from malloc, and whether
# realloc keeps a block, is the allocator's choice (scudo and jemalloc hand a just-freed block of the same size class
# back, and keep a block whose new size still fits it), and an emulator check can test it: a bump heap that never
# reuses and always moves answers both the same way in two runs. Run A (heap_classes False) never reuses and always
# moves; run B (heap_classes True) reuses and resizes in place wherever a device's allocator might, so a result that
# depends on either choice differs between the runs and declines.
# sizes every Android allocator serves from one class: jemalloc's 8, 16, 32, 48 and 64 (16-byte quantum) and scudo's
# first four (16-byte steps less its 16-byte header) end at the same request sizes. A pair wrongly put here costs only
# a decline (run B reuses where a device would not, run A never does).
_HEAP_SAME = ((1, 8), (9, 16), (17, 32), (33, 48), (49, 64))
# request sizes at which BOTH scudo (Android's 64-bit size classes less their 16-byte header) and jemalloc end a class:
# two sizes on either side of one are served from two classes by both. This list is the one the never-wrong argument
# rests on (a pair wrongly called apart is a reuse neither run makes and a device does), so it holds only the class ends
# of the 16-byte steps every 64-bit Android allocator starts with; past 64 bytes only the ratio rule calls sizes apart.
_HEAP_SPLIT = (16, 32, 48, 64)


def _heap_room(n):
    """The room run B keeps for a block first asked for `n` bytes: twice the request rounded up to 16, at least 32.
    That is more than any Android allocator's usable size for the request (scudo's largest ratio is about 1.97,
    jemalloc's 2 at its 8-byte class), so a resize a device makes in place, run B makes in place too."""
    return max(32, (2 * n + 15) & ~15)


def _heap_same(s, t):
    """Every Android allocator serves requests of s and t bytes from one size class."""
    return s == t or any(lo <= s <= hi and lo <= t <= hi for lo, hi in _HEAP_SAME)


def _heap_apart(s, t):
    """No Android allocator serves requests of s and t bytes from one size class (so a freed block first asked for
    one never comes back for the other): a class end both allocators share lies between them, or the larger is more
    than twice the smaller and 64 bytes."""
    lo, hi = min(s, t), max(s, t)
    return any(lo <= b < hi for b in _HEAP_SPLIT) or hi > 2 * lo + 64

# ---------------------------------------------------------------------------------------------------- libc
LIBC_FUNCS = (
    "strlen", "memcpy", "memmove", "memset", "memcmp", "strcmp", "strncmp", "strcpy", "strncpy", "strchr",
    "malloc", "calloc", "realloc", "free", "__stack_chk_fail",
    "__strlen_chk", "__memcpy_chk", "__memmove_chk", "__memset_chk", "__strcpy_chk", "__strncpy_chk",
    "__strchr_chk",
    "__cxa_atexit",            # registers a destructor for exit/dlclose only: 0, nothing a call can observe
    # liblog (KB-2 fix round 1): a line to the device log, nothing the program can read back; the result is a
    # device's choice (1 written, -EPERM below the log level), so the two layouts answer 1 and -1 (log_ret)
    "__android_log_print", "__android_log_write", "__android_log_vprint",
)
# Weak undefined toolchain hooks that no Android or glibc runtime library defines: the loader resolves a weak
# undefined symbol nobody defines to 0 (crtbegin's frame_dummy / _init test them and skip the call).
_WEAK_ZERO = {"_ITM_registerTMCloneTable", "_ITM_deregisterTMCloneTable", "__gmon_start__", "_Jv_RegisterClasses"}
_LIBC_ID = {n: 1 + i for i, n in enumerate(LIBC_FUNCS)}
# A preemptible definition with one of these names could be interposed by the system's libc at run time.
_INTERPOSABLE = set(LIBC_FUNCS) | {"strrchr", "strstr", "strcat", "strncat", "printf", "sprintf", "snprintf",
                                   "puts", "abort", "exit", "rand", "srand", "time", "getpid", "__errno"}

# ---------------------------------------------------------------------------------------------------- JNI
# JNINativeInterface slot names in table order (jni.h); slots 0-3 are reserved (NULL in a real JNIEnv).
JNI_SLOTS = (
    "reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass", "FindClass",
    "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom",
    "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear",
    "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
    "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV",
    "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID",
) + tuple("Call%sMethod%s" % (t, s) for t in ("Object", "Boolean", "Byte", "Char", "Short", "Int", "Long",
                                              "Float", "Double", "Void") for s in ("", "V", "A")) + \
    tuple("CallNonvirtual%sMethod%s" % (t, s) for t in ("Object", "Boolean", "Byte", "Char", "Short", "Int",
                                                        "Long", "Float", "Double", "Void") for s in ("", "V", "A")) + \
    ("GetFieldID",) + tuple("Get%sField" % t for t in ("Object", "Boolean", "Byte", "Char", "Short", "Int", "Long",
                                                       "Float", "Double")) + \
    tuple("Set%sField" % t for t in ("Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")) + \
    ("GetStaticMethodID",) + tuple("CallStatic%sMethod%s" % (t, s) for t in ("Object", "Boolean", "Byte", "Char",
                                                                             "Short", "Int", "Long", "Float",
                                                                             "Double", "Void")
                                   for s in ("", "V", "A")) + \
    ("GetStaticFieldID",) + tuple("GetStatic%sField" % t for t in ("Object", "Boolean", "Byte", "Char", "Short",
                                                                   "Int", "Long", "Float", "Double")) + \
    tuple("SetStatic%sField" % t for t in ("Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float",
                                           "Double")) + \
    ("NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF",
     "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray",
     "GetObjectArrayElement", "SetObjectArrayElement") + \
    tuple("New%sArray" % t for t in ("Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")) + \
    tuple("Get%sArrayElements" % t for t in ("Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")) + \
    tuple("Release%sArrayElements" % t for t in ("Boolean", "Byte", "Char", "Short", "Int", "Long", "Float",
                                                 "Double")) + \
    tuple("Get%sArrayRegion" % t for t in ("Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")) + \
    tuple("Set%sArrayRegion" % t for t in ("Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")) + \
    ("RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
     "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical",
     "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck",
     "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType",
     "GetModule")
JNI_INDEX = {n: i for i, n in enumerate(JNI_SLOTS)}
assert JNI_INDEX["GetStringUTFChars"] == 169 and JNI_INDEX["ExceptionCheck"] == 228
# B-241: the reference lifecycle (see _Run._jni_lifecycle); each is exact under the model's rules or declines
JNI_LIFECYCLE = frozenset({"NewGlobalRef", "DeleteGlobalRef", "NewLocalRef", "NewWeakGlobalRef",
                           "DeleteWeakGlobalRef", "PushLocalFrame", "PopLocalFrame", "EnsureLocalCapacity",
                           "GetObjectRefType", "IsSameObject", "GetJavaVM", "MonitorEnter", "MonitorExit"})
# The most local references a frame may ask for: every ART version grants this many to a native that holds a
# handful (ART before Android 8 capped the whole table at 512 and failed a larger request; later ones grow it).
LOCAL_FRAME_CAPACITY = 256
MAX_LOCAL_FRAMES = 64
JNI_REF_TYPES = {"local": 1, "global": 2, "weak": 3}      # jobjectRefType; 0 is JNIInvalidRefType (NULL)
JNI_MODELLED = {"GetStringUTFChars", "ReleaseStringUTFChars", "GetStringUTFLength", "GetStringLength",
                "NewStringUTF", "GetArrayLength", "GetByteArrayElements", "ReleaseByteArrayElements",
                "GetByteArrayRegion", "SetByteArrayRegion", "NewByteArray", "GetIntArrayElements",
                "ReleaseIntArrayElements", "ExceptionCheck",
                # exact because the model never has a pending exception (every throwing path declines) and
                # FindClass answers only a class the delivery's own dex defines (load_info / call_jni `classes`)
                "GetVersion", "ExceptionOccurred", "ExceptionClear", "DeleteLocalRef", "FindClass",
                "RegisterNatives"} | JNI_LIFECYCLE
JNI_TABLE_SLOTS = 240          # (unused since KB-2 fix round 3: the table holds len(JNI_SLOTS) slots, reserved0..3
                               # NULL, every other a trap EXCEPT GetModule (slot 233, JNI >= 9), left undefined;
                               # a read at or past GetModule is undefined)
# JNIInvokeInterface (the JavaVM a JNI_OnLoad receives), jni.h order; slots 0-2 are reserved.
VM_SLOTS = ("reserved0", "reserved1", "reserved2", "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread",
            "GetEnv", "AttachCurrentThreadAsDaemon")
JNI_VERSIONS_GETENV = (0x00010001, 0x00010002, 0x00010004, 0x00010006)
JNI_VERSIONS_ONLOAD = (0x00010002, 0x00010004, 0x00010006)   # ART's IsBadJniVersion accepts only these
MAX_REGISTER = 4096            # entries one RegisterNatives may pass

TRAP_SENTINEL = 0
TRAP_VM_BASE = 200
TRAP_JNI_BASE = 256
TRAP_IMPORT_BASE = 512
TRAP_COUNT = 768
JNI_COMMIT = 1
JNI_ABORT = 2

# relocation types
_X86 = dict(NONE=0, ABS=1, COPY=5, GLOB=6, JUMP=7, REL=8, IREL=37)
_A64 = dict(NONE=0, ABS=257, COPY=1024, GLOB=1025, JUMP=1026, REL=1027, IREL=1032)

# Instructions whose result depends on the machine or the moment, not on the bytes (an emulator check reads them:
# a timing gap, the hypervisor bit, a hardware random number): executing one declines. x86 is checked per
# executed block (capstone, cached per image); AArch64 system-register access through Unicorn's MRS/MSR/SYS
# hooks, with the ordinary user state (TPIDR_EL0, NZCV, FPCR, FPSR) allowed. The sets are native_emulate's.
_X86_ENV_INSNS = _ne.X86_ENV_INSNS
# B-241: x86 floating-point instructions whose RESULT a processor family chooses: the reciprocal estimates
# (Intel and AMD return different low bits within the documented error bound) and the x87 transcendentals
# (their last bits differ between processors, and the engine computes them its own way). Both runs get the
# engine's answer, so the double run cannot catch them: executing one declines. AArch64 has no such
# instruction (FRECPE / FRSQRTE are fixed by the architecture's pseudocode).
_X86_FP_INEXACT = frozenset({
    "rsqrtss", "rsqrtps", "rcpss", "rcpps", "vrsqrtss", "vrsqrtps", "vrcpss", "vrcpps",
    "fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1"})
_A64_MRS_OK = _ne.A64_MRS_OK
_A64_MSR_OK = _ne.A64_MSR_OK


def _sx32(v):
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


try:
    from capstone import Cs as _Cs, CS_ARCH_X86 as _CS_ARCH_X86, CS_MODE_64 as _CS_MODE_64
    _CS_X86 = _Cs(_CS_ARCH_X86, _CS_MODE_64)
except Exception:                                      # without capstone no x86 image is emulated (fail closed)
    _CS_X86 = None


def _x86_block_problem(code):
    """The first environment-dependent mnemonic in one translated x86-64 block, '' when there is none, or a
    reason when capstone cannot decode the whole block (then the block is not vetted: a decline)."""
    n = 0
    for ins in _CS_X86.disasm(code, 0):
        if ins.mnemonic in _X86_ENV_INSNS or ins.mnemonic in _X86_FP_INEXACT:
            return ins.mnemonic
        n += ins.size
    return "" if n == len(code) else "an instruction capstone cannot decode"


class _Sym:
    __slots__ = ("name", "value", "size", "type", "bind", "vis", "shndx")

    def __init__(self, name, value, size, typ, bind, vis, shndx):
        self.name, self.value, self.size, self.type, self.bind, self.vis, self.shndx = \
            name, value, size, typ, bind, vis, shndx


# ==================================================================================================== ELF
class ElfImage:
    """A parsed ELF64 little-endian ET_DYN/ET_EXEC image (x86-64 or AArch64), with its relocation plan.

    Parsing reads what the LOADER reads (program headers, PT_DYNAMIC and the tables it names); section
    headers are optional and only add the static .symtab (local symbols, for emulate_symbol). Anything the
    loader would do that is not modelled sets `problem`, and every emulation of the image then declines."""

    def __init__(self, data):
        self.data = data = bytes(data)
        self.problem = None
        if len(data) > MAX_ELF or len(data) < 64 or data[:4] != b"\x7fELF":
            raise EmulationError("not an ELF image")
        if data[4] != 2 or data[5] != 1:
            raise EmulationError("only ELF64 little-endian images are emulated")
        self.etype, self.machine = struct.unpack_from("<HH", data, 16)
        if self.etype not in (ET_DYN, ET_EXEC):
            raise EmulationError("ELF type %d is not loadable" % self.etype)
        if self.machine == EM_X86_64:
            self.arch, self.R = ARCH_X86_64, _X86
        elif self.machine == EM_AARCH64:
            self.arch, self.R = ARCH_ARM64, _A64
        else:
            raise EmulationError("e_machine %d is not emulated" % self.machine)
        e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
        if e_phentsize != 56 or not (0 < e_phnum <= 64) or e_phoff + 56 * e_phnum > len(data):
            raise EmulationError("bad program headers")
        self.loads, self.dynamic, self.relro, self.has_tls = [], None, None, False
        for i in range(e_phnum):
            p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from(
                "<IIQQQQQQ", data, e_phoff + 56 * i)
            if p_type == 1:                                    # PT_LOAD
                if p_filesz > p_memsz or p_off + p_filesz > len(data) or p_memsz > MAX_SPAN:
                    raise EmulationError("bad PT_LOAD")
                if p_memsz and p_off % PAGE != p_vaddr % PAGE:
                    # bionic maps the file page at page_start(p_vaddr): with p_offset and p_vaddr not congruent the
                    # bytes would land shifted (or the loader refuses the library); never read them unshifted
                    raise EmulationError("a PT_LOAD whose file offset and address are not congruent modulo the page")
                if p_memsz:
                    self.loads.append((p_vaddr, p_memsz, p_filesz, p_off, p_flags))
            elif p_type == 2:                                  # PT_DYNAMIC
                self.dynamic = (p_vaddr, p_memsz)
            elif p_type == 0x6474E552:                         # PT_GNU_RELRO
                self.relro = (p_vaddr, p_memsz)
            elif p_type == 7:                                  # PT_TLS
                self.has_tls = True
        if not self.loads:
            raise EmulationError("no PT_LOAD")
        if any((fl & 3) == 3 for (_v, _m, _f, _o, fl) in self.loads):
            raise EmulationError("a PT_LOAD both writable and executable (bionic refuses to load it)")
        self.loads.sort()
        for (a, m, _f, _o, _fl), (b, _m2, _f2, _o2, _fl2) in zip(self.loads, self.loads[1:]):
            if a + m > b:
                raise EmulationError("overlapping PT_LOAD segments")
        self.lo = self.loads[0][0] & ~(PAGE - 1)
        self.hi = (self.loads[-1][0] + self.loads[-1][1] + PAGE - 1) & ~(PAGE - 1)
        if self.hi - self.lo > MAX_SPAN:
            raise EmulationError("image span too large")
        # Every runtime region of both layouts (stack, heap, TLS, JNIEnv, traps) sits at or above 0x6123_0000_0000
        # and an ET_DYN image is placed at 0x007A_E5A3_C000 or 0x7F35_1A5C_3000 (its vaddrs below 2^36, so it ends
        # below 0x008A_E5A3_C000 or 0x7F45_1A5C_3000): keep an image clear of all of them.
        if self.etype == ET_EXEC and (self.lo < 0x10000 or self.hi > 0x5000_0000_0000):
            raise EmulationError("ET_EXEC outside the modelled address range")
        if self.etype == ET_DYN and self.hi > (1 << 36):
            raise EmulationError("ET_DYN vaddr range outside the modelled address range")
        self._parse_dynamic()
        self._parse_sections(e_shoff, e_shentsize, e_shnum, e_shstrndx)
        self._plan()
        self.constructors()                  # parsed once (an unexpected table size sets `problem`)

    # --------------------------------------------------------------- load-time code
    def constructors(self):
        """[(kind, vaddr)] of the load-time code the loader runs before any call, in bionic's order: DT_INIT,
        then every DT_INIT_ARRAY slot (its relocated value is read at run time: ('array', slot vaddr)). An
        executable's DT_PREINIT_ARRAY comes first; a shared object's is ignored, as bionic and glibc ignore it."""
        cached = getattr(self, "_ctors", None)
        if cached is not None:
            return list(cached)
        out = []
        g = lambda t: self.dyn.get(t, [None])[0]   # noqa: E731
        for (tag_a, tag_s, only_exec) in ((32, 33, True), (None, None, False), (25, 27, False)):
            if tag_a is None:
                if g(12):
                    out.append(("func", g(12)))
                continue
            if only_exec and self.etype != ET_EXEC:
                continue
            va, sz = g(tag_a), g(tag_s) or 0
            if va is None or not sz:
                continue
            if sz % 8 or sz > 8 * 4096:
                self.problem = self.problem or "a constructor array of an unexpected size"
                continue
            out += [("array", va + 8 * k) for k in range(sz // 8)]
        self._ctors = tuple(out)
        return list(out)

    def section_constructors(self):
        """True when the image has no PT_DYNAMIC (a static executable) but its section headers name a
        non-empty constructor table the dynamic tags would not tell (.init_array / .preinit_array / .ctors)."""
        return bool(getattr(self, "_sec_ctors", False)) and self.dynamic is None

    def has_load_code(self, jni=False):
        """True when the loader would run code of this image before a call (constructors; with `jni`, the
        JNI_OnLoad ART calls from System.loadLibrary)."""
        if self.constructors() or self.section_constructors():
            return True
        return bool(jni and "JNI_OnLoad" in self.exports())

    # --------------------------------------------------------------- address helpers
    def seg_of(self, vaddr):
        for seg in self.loads:
            if seg[0] <= vaddr < seg[0] + seg[1]:
                return seg
        return None

    def file_bytes(self, vaddr, n):
        """`n` file-backed bytes at `vaddr` (inside one PT_LOAD's filesz), else EmulationError."""
        for (va, _m, fs, off, _fl) in self.loads:
            if va <= vaddr and vaddr + n <= va + fs:
                return self.data[off + vaddr - va: off + vaddr - va + n]
        raise EmulationError("table at %#x is not file-backed" % vaddr)

    def _cstr(self, vaddr, limit=4096):
        for (va, _m, fs, off, _fl) in self.loads:
            if va <= vaddr < va + fs:
                start = off + vaddr - va
                end = self.data.find(b"\x00", start, min(off + fs, start + limit))
                if end < 0:
                    raise EmulationError("unterminated string")
                return self.data[start:end].decode("latin1")
        raise EmulationError("string at %#x not file-backed" % vaddr)

    # --------------------------------------------------------------- dynamic section
    def _parse_dynamic(self):
        self.dyn = {}
        self.dynsyms = []
        self.relocs = []                     # (offset, type, symidx, addend, implicit)
        self.symbolic = False
        if self.dynamic is None:
            return
        va, sz = self.dynamic
        raw = self.file_bytes(va, min(sz, 16 * 512) // 16 * 16)
        for k in range(len(raw) // 16):
            tag, val = struct.unpack_from("<qQ", raw, 16 * k)
            if tag == 0:
                break
            self.dyn.setdefault(tag, []).append(val)
        g = lambda t: self.dyn.get(t, [None])[0]   # noqa: E731
        if g(0x6000000F) is not None:                                  # DT_ANDROID_REL
            # a 64-bit bionic reads packed relocations as RELA only ("unsupported DT_ANDROID_REL")
            self.problem = "DT_ANDROID_REL in a 64-bit image (bionic refuses to load it)"
        if g(22) is not None or (g(30) or 0) & 0x4:                    # DT_TEXTREL / DF_TEXTREL
            self.problem = "text relocations are not modelled"
        self.symbolic = g(16) is not None or bool((g(30) or 0) & 0x2)
        strtab, strsz, symtab = g(5), g(10), g(6)
        self._strtab = (strtab, strsz)
        nsyms = self._dynsym_count(symtab)
        if symtab is not None and nsyms:
            ent = g(11) or 24
            if ent != 24:
                raise EmulationError("unexpected DT_SYMENT")
            raw = self.file_bytes(symtab, 24 * nsyms)
            for k in range(nsyms):
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", raw, 24 * k)
                name = ""
                if st_name and strtab is not None:
                    if strsz is not None and st_name >= strsz:
                        raise EmulationError("symbol name outside DT_STRTAB")
                    name = self._cstr(strtab + st_name)
                self.dynsyms.append(_Sym(name, st_value, st_size, st_info & 15, st_info >> 4, st_other & 3, st_shndx))
        if g(0x60000011) is not None:                                  # DT_ANDROID_RELA (APS2): applied first
            try:
                self.relocs += self._read_aps2(g(0x60000011), g(0x60000012) or 0)
            except EmulationError as e:
                # the loader refuses the library (or reads past the table): an image problem, like the others
                self.problem = self.problem or "Android packed relocations: %s" % e
        self._read_relocs(g(7), g(8), g(9) or 24, True)                # DT_RELA
        self._read_relocs(g(17), g(18), g(19) or 16, False)            # DT_REL
        if g(23) is not None:                                          # DT_JMPREL
            pltrel = g(20)
            self._read_relocs(g(23), g(2), 24 if pltrel == 7 else 16, pltrel == 7)
        for tag_addr, tag_size in ((36, 35), (0x6FFFE000, 0x6FFFE001)):   # DT_RELR / DT_ANDROID_RELR
            if g(tag_addr) is not None:
                self._read_relr(g(tag_addr), g(tag_size) or 0)
        if len(self.relocs) > MAX_RELOCS:
            raise EmulationError("too many relocations")

    def _dynsym_count(self, symtab):
        g = lambda t: self.dyn.get(t, [None])[0]   # noqa: E731
        if symtab is None:
            return 0
        if g(4) is not None:                                           # DT_HASH: nchain
            nb, nc = struct.unpack("<II", self.file_bytes(g(4), 8))
            if nc > MAX_SYMS:
                raise EmulationError("too many dynamic symbols")
            return nc
        if g(0x6FFFFEF5) is not None:                                  # DT_GNU_HASH
            h = g(0x6FFFFEF5)
            nbuckets, symoffset, bloom_size, _shift = struct.unpack("<IIII", self.file_bytes(h, 16))
            if nbuckets > MAX_SYMS or bloom_size > MAX_SYMS:
                raise EmulationError("bad DT_GNU_HASH")
            bstart = h + 16 + 8 * bloom_size
            buckets = struct.unpack("<%dI" % nbuckets, self.file_bytes(bstart, 4 * nbuckets)) if nbuckets else ()
            last = max(buckets) if buckets else 0
            if last < symoffset:
                return symoffset
            cstart = bstart + 4 * nbuckets
            idx = last
            while idx - symoffset < MAX_SYMS:
                w = struct.unpack("<I", self.file_bytes(cstart + 4 * (idx - symoffset), 4))[0]
                if w & 1:
                    return idx + 1
                idx += 1
            raise EmulationError("unterminated DT_GNU_HASH chain")
        return 0                                                       # filled from section headers, if any

    def _read_relocs(self, addr, size, ent, rela):
        if addr is None or not size:
            return
        if ent != (24 if rela else 16) or size % ent:
            raise EmulationError("unexpected relocation entry size")
        n = size // ent
        if n > MAX_RELOCS:
            raise EmulationError("too many relocations")
        raw = self.file_bytes(addr, size)
        for k in range(n):
            if rela:
                off, info, add = struct.unpack_from("<QQq", raw, 24 * k)
                self.relocs.append((off, info & M32, info >> 32, add, False))
            else:
                off, info = struct.unpack_from("<QQ", raw, 16 * k)
                self.relocs.append((off, info & M32, info >> 32, 0, True))

    def _read_aps2(self, addr, size):
        """Android packed relocations (DT_ANDROID_RELA / DT_ANDROID_RELASZ): the magic "APS2", then signed
        LEB128 numbers: the relocation count, the first offset, then groups. Decoded step for step as bionic's
        packed_reloc_iterator (linker_reloc_iterators.h) decodes them, so the rows are the ones the device's
        loader applies: a group's flags say whether its relocations share one offset delta (2), one r_info (1)
        and one addend delta (8 with 4), or carry their own addend deltas (8 without 4); a group without
        addends resets the running addend to 0. Bytes after the last relocation are ignored, as bionic ignores
        them (lld pads the section so its size never shrinks). A bad magic, a number that runs past the table
        and a count over the relocation cap raise (the loader refuses the first, reads out of bounds on the
        second); the caller turns that into the image's `problem`. Returns the rows."""
        if size < 4 or size > 16 * MAX_RELOCS:
            raise EmulationError("bad Android packed relocation table size")
        raw = self.file_bytes(addr, size)
        if raw[:4] != b"APS2":
            raise EmulationError("bad Android packed relocation header (bionic refuses to load it)")
        pos = 4

        def sleb():
            nonlocal pos
            value = shift = 0
            while True:
                if pos >= len(raw):
                    raise EmulationError("truncated Android packed relocations")
                byte = raw[pos]
                pos += 1
                value |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
                if shift >= 70:
                    raise EmulationError("an Android packed relocation number longer than 64 bits")
            if byte & 0x40 and shift < 64:
                value |= -(1 << shift)
            return value & M64

        count, offset = sleb(), sleb()
        if count > MAX_RELOCS:
            raise EmulationError("too many relocations")
        info = addend = delta = flags = 0
        group_size = group_index = 0
        rows = []
        for _ in range(count):
            if group_index == group_size:
                group_size, flags = sleb(), sleb()
                if flags & 2:                                  # RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
                    delta = sleb()
                if flags & 1:                                  # RELOCATION_GROUPED_BY_INFO_FLAG
                    info = sleb()
                if flags & 8 and flags & 4:                    # GROUP_HAS_ADDEND and GROUPED_BY_ADDEND
                    addend = (addend + sleb()) & M64
                elif not flags & 8:
                    addend = 0
                group_index = 0
            offset = (offset + (delta if flags & 2 else sleb())) & M64
            if not flags & 1:
                info = sleb()
            if flags & 8 and not flags & 4:
                addend = (addend + sleb()) & M64
            group_index += 1
            rows.append((offset, info & M32, info >> 32, addend - (1 << 64) if addend >> 63 else addend, False))
        return rows

    def _read_relr(self, addr, size):
        if size % 8:
            raise EmulationError("bad DT_RELRSZ")
        if size // 8 > MAX_RELOCS:
            # KB-2 fix round 1 (review of e281f95): a table of more words than the relocation cap is refused before
            # it is walked (an 8 MiB table of empty bitmap words cost 1 s to parse)
            raise EmulationError("too many relocations")
        raw = self.file_bytes(addr, size)
        rel = self.R["REL"]
        where = 0
        for (e,) in struct.iter_unpack("<Q", raw):
            if not e & 1:
                self.relocs.append((e, rel, 0, 0, True))
                where = e + 8
            else:
                bits = e >> 1
                while bits:                                   # the set bits only, lowest first (as before)
                    low = bits & -bits
                    self.relocs.append((where + 8 * (low.bit_length() - 1), rel, 0, 0, True))
                    bits ^= low
                where += 8 * 63
            if len(self.relocs) > MAX_RELOCS:
                raise EmulationError("too many relocations")

    # --------------------------------------------------------------- section headers (optional)
    def _parse_sections(self, shoff, shentsize, shnum, shstrndx):
        self.symtab = []
        self._sec_ctors = False
        if not shoff or not shnum or shentsize != 64 or shoff + 64 * shnum > len(self.data) or shnum > 4096:
            return
        try:
            secs = [struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + 64 * i) for i in range(shnum)]
            if shstrndx < shnum:
                n_off, n_size = secs[shstrndx][4], secs[shstrndx][5]
                for (nm, typ, _f, _addr, _off, size, _l, _i, _a, _e) in secs:
                    if typ == 8 or nm >= n_size:
                        continue
                    end = self.data.find(b"\x00", n_off + nm, n_off + n_size)
                    sname = self.data[n_off + nm:end] if end >= 0 else b""
                    if typ in (14, 16) or sname in (b".init_array", b".preinit_array"):
                        self._sec_ctors = self._sec_ctors or size > 0
                    elif sname == b".ctors":
                        self._sec_ctors = self._sec_ctors or size > 16
            for (_n, typ, _f, addr, off, size, link, _i, _a, ent) in secs:
                if typ == 11 and not self.dynsyms and addr and self.dyn.get(6, [None])[0] == addr and ent == 24:
                    self._fill_dynsym_from_section(off, size, secs[link] if link < shnum else None)
                if typ == 2 and ent == 24 and off + size <= len(self.data) and link < shnum:
                    s_off, s_size = secs[link][4], secs[link][5]
                    for k in range(min(size // 24, MAX_SYMS)):
                        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                            "<IBBHQQ", self.data, off + 24 * k)
                        if st_name >= s_size:
                            continue
                        p = s_off + st_name
                        end = self.data.find(b"\x00", p, s_off + s_size)
                        if end < 0:
                            continue
                        self.symtab.append(_Sym(self.data[p:end].decode("latin1"), st_value, st_size, st_info & 15,
                                                st_info >> 4, st_other & 3, st_shndx))
        except (struct.error, IndexError, UnicodeDecodeError):
            self.symtab = []

    def _fill_dynsym_from_section(self, off, size, strsec):
        if strsec is None:
            return
        s_off, s_size = strsec[4], strsec[5]
        for k in range(min(size // 24, MAX_SYMS)):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", self.data, off + 24 * k)
            p = s_off + st_name
            end = self.data.find(b"\x00", p, s_off + s_size)
            name = self.data[p:end].decode("latin1") if (st_name and end >= 0) else ""
            self.dynsyms.append(_Sym(name, st_value, st_size, st_info & 15, st_info >> 4, st_other & 3, st_shndx))

    # --------------------------------------------------------------- symbols
    def _in_exec(self, vaddr):
        seg = self.seg_of(vaddr)
        return seg is not None and bool(seg[4] & 1)

    def exports(self):
        """{name: vaddr} of the functions the dynamic linker would hand to dlsym: defined, global or weak,
        default or protected visibility, FUNC or NOTYPE, inside an executable segment."""
        out = getattr(self, "_exports", None)
        if out is None:
            out, amb = {}, set()
            for s in self.dynsyms:
                if (s.name and s.shndx not in (0, 0xFFF1, 0xFFF2) and s.bind in (1, 2) and s.vis in (0, 3)
                        and s.type in (0, 2) and self._in_exec(s.value)):
                    if out.setdefault(s.name, s.value) != s.value:
                        amb.add(s.name)
            self._exports = out
            self._amb_exports = frozenset(amb)
        return dict(out)

    def ambiguous_exports(self):
        """Names the dynamic symbol table defines twice with different addresses: which one a lookup finds
        depends on the hash chain the loader walks, so a caller must not bind either."""
        self.exports()
        return self._amb_exports

    def symbol(self, name, allow_local=True):
        """vaddr of a defined function symbol (exports first, then the static .symtab), else None."""
        ex = self.exports()
        if name in ex:
            return ex[name]
        if allow_local:
            for s in self.symtab:
                if s.name == name and s.shndx not in (0, 0xFFF1, 0xFFF2) and s.type in (0, 2) and self._in_exec(s.value):
                    return s.value
        return None

    # --------------------------------------------------------------- relocation plan
    def _plan(self):
        """Base-relative relocation plan: (offset, kind, payload) with kind rel/abs/sym/trap/poison."""
        self.plan = []
        R = self.R
        for (off, typ, si, add, implicit) in self.relocs:
            seg = self.seg_of(off)
            if seg is None or not (seg[4] & 2) or (seg[4] & 1) or off + 8 > seg[0] + seg[1]:
                self.problem = self.problem or "relocation at %#x outside a writable, non-executable segment" % off
                continue
            if typ == R["NONE"]:
                continue
            if implicit:
                if off >= seg[0] + seg[2]:
                    add = 0                                # in the zero-filled tail: the place holds 0
                else:
                    try:
                        add = struct.unpack("<q", self.file_bytes(off, 8))[0]
                    except EmulationError:
                        self.plan.append((off, "poison", 8))   # straddles the file-backed end
                        continue
            if typ == R["REL"]:
                self.plan.append((off, "rel", add))
                continue
            if typ not in (R["ABS"], R["GLOB"], R["JUMP"]):
                if typ == R["IREL"]:
                    # KB-2 fix round 2: an IRELATIVE resolver is code the loader runs while it relocates, before any
                    # JNI call (it may reach the JavaVM and register natives, as a constructor may): not modelled
                    self.problem = self.problem or "an IRELATIVE relocation runs its resolver at load time"
                self.plan.append((off, "poison", 16))      # TLS, COPY, IRELATIVE, TLSDESC, unknown
                continue
            if si >= len(self.dynsyms) or si == 0:
                self.plan.append((off, "poison", 8))
                continue
            sym = self.dynsyms[si]
            if typ in (R["GLOB"], R["JUMP"]) and add:
                # bionic computes S + A for GLOB_DAT / JUMP_SLOT, glibc's x86-64 loader S alone: a non-zero
                # addend makes the slot's value depend on the loader, so the slot is undefined.
                self.plan.append((off, "poison", 8))
                continue
            if sym.shndx == 0:                             # an import
                if sym.name in _LIBC_ID and add == 0 and sym.type in (0, 2):
                    self.plan.append((off, "trap", _LIBC_ID[sym.name]))
                elif sym.bind == 2 and sym.name in _WEAK_ZERO and typ != R["JUMP"]:
                    self.plan.append((off, "abs", add & M64))   # weak, defined by no runtime library: 0
                elif typ == R["JUMP"] and sym.name:
                    self.plan.append((off, "import", sym.name))
                else:
                    self.plan.append((off, "poison", 8))
                continue
            if sym.type in (6, 10):                        # STT_TLS, STT_GNU_IFUNC
                if sym.type == 10:
                    # a slot bound to an IFUNC runs its resolver at load time (KB-2 fix round 2): not modelled
                    self.problem = self.problem or "a relocation against an IFUNC runs its resolver at load time"
                self.plan.append((off, "poison", 8))
                continue
            if sym.shndx == 0xFFF1:                        # SHN_ABS
                self.plan.append((off, "abs", (sym.value + add) & M64))
                continue
            preempt = (self.etype == ET_DYN and sym.bind in (1, 2) and sym.vis == 0 and not self.symbolic)
            if preempt and sym.name in _INTERPOSABLE:
                self.plan.append((off, "poison", 8))       # the system libc may interpose it: ambiguous
                continue
            self.plan.append((off, "sym", (sym.value + add) & M64))


_CACHE = {}
_CACHE_ORDER = []
# a thin 64-bit Mach-O (little-endian) and the two universal headers (big-endian)
_MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")


def load(elf_bytes, arch=None, macho=False):
    """The parsed image of `elf_bytes` (cached by content hash): an ElfImage, or, when the caller opts in with
    `macho=True`, for a 64-bit Mach-O file (B-241) a macho_image.MachOImage with the same shape. Without the
    opt-in a Mach-O file is refused by name: no Android or ELF loader would load one, so a caller that reads
    ELF libraries must decline on it, never answer from it. `arch` names the slice of a universal Mach-O file
    that holds more than one this engine runs; it is not used for an ELF. Raises EmulationError."""
    data = bytes(elf_bytes)
    is_macho = data[:4] in _MACHO_MAGICS
    if is_macho and not macho:
        raise EmulationError("a Mach-O (or universal) file, not an ELF: only a caller that runs Mach-O "
                             "(load(..., macho=True)) takes one")
    macho = is_macho
    key = hashlib.sha256(data).digest()
    if macho and arch is not None:
        key = hashlib.sha256(key + arch.encode()).digest()
    img = _CACHE.get(key)
    if img is None:
        if macho:
            import macho_image as _macho
            img = _macho.MachOImage(data, arch=arch, libc_ids=_LIBC_ID)
        else:
            img = ElfImage(data)
        img.content_digest = key             # the SHA-256 content key (callers cache by it)
        _CACHE[key] = img
        _CACHE_ORDER.append(key)
        while len(_CACHE_ORDER) > 16:
            _CACHE.pop(_CACHE_ORDER.pop(0), None)
    return img


# ==================================================================================================== Java values
class JStr:
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


class JArr:
    __slots__ = ("kind", "values", "arg")

    def __init__(self, kind, values, arg=None):
        self.kind = kind          # 'B' (signed bytes), 'I' (signed ints), or another letter / '?'
        self.values = values      # a COPY of the Java array (the caller's list is changed only on commit)
        self.arg = arg            # the argument index this array came from, or None for a new array


class JOpaque:
    __slots__ = ("tag",)

    def __init__(self, tag):
        self.tag = tag


class JClass:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name          # internal name, a/b/C


def _mutf8_encode(text):
    """GetStringUTFChars bytes of `text`, or EmulationError where modified UTF-8 and UTF-8 part ways or an
    implementation could differ (U+0000, a supplementary character, a lone surrogate)."""
    for ch in text:
        o = ord(ch)
        if o == 0 or o > 0xFFFF or 0xD800 <= o <= 0xDFFF:
            raise SetupError("string holds a character whose JNI encoding is not modelled")
    return text.encode("utf-8")


def _mutf8_decode(raw):
    """NewStringUTF of `raw` (no NUL), strict: standard UTF-8 of BMP characters only, else EmulationError."""
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise EmulationError("NewStringUTF of bytes that are not strict UTF-8")
    for ch in text:
        o = ord(ch)
        if o > 0xFFFF or 0xD800 <= o <= 0xDFFF:
            raise EmulationError("NewStringUTF of a character whose JNI decoding is not modelled")
    return text


def _utf16_len(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


# ==================================================================================================== one run
class _Region:
    __slots__ = ("lo", "hi", "defined", "writable", "name")

    def __init__(self, lo, hi, name):
        self.lo, self.hi, self.name = lo, hi, name
        self.defined = bytearray(hi - lo)
        self.writable = bytearray(hi - lo)


_ONES = [bytes([1]) * n for n in range(129)]


def _ones(n):
    return _ONES[n] if n < len(_ONES) else b"\x01" * n


def _layout_trap(L, tid):
    idx = (TRAP_COUNT - 1 - tid) if L["trap_rev"] else tid
    return L["trap"] + L["trap_off"] + L["trap_step"] * idx


def _trap_id(L, addr):
    rel = addr - (L["trap"] + L["trap_off"])
    if rel < 0 or rel % L["trap_step"] or rel // L["trap_step"] >= TRAP_COUNT:
        return None
    idx = rel // L["trap_step"]
    return (TRAP_COUNT - 1 - idx) if L["trap_rev"] else idx


_LAID = {}                     # (image key, layout) -> _laid_out state (small images only, a short LRU)
_LAID_ORDER = []
_LAID_MAX_SPAN = 2 << 20       # an image larger than this is laid out again on every run (memory, not speed)
_LAID_MAX = 8


def _laid_out(img, layout_index):
    """What the loader leaves in memory for `img` in one layout, before any code runs: the runs of pages to map
    (start, end, protection), the image bytes after every relocation (one buffer over the image span), the
    definedness and writability shadows, the executable-page gaps, the import trap table and the RELRO range.
    A pure function of the image and the layout: built on a buffer (a relocation is a pack_into, not a
    mem_write) and cached for a small image, so a call into it maps the image with a few mem_writes."""
    key = (id(img), layout_index)
    got = _LAID.get(key)
    if got is not None and got["img"] is img:
        return got
    L = _LAYOUTS[layout_index]
    b = L["image"] if img.etype == ET_DYN else 0
    lo, hi = img.lo, img.hi
    mem = bytearray(hi - lo)
    defined = bytearray(hi - lo)
    writable = bytearray(hi - lo)
    perms = {}
    for (va, m, fs, off, fl) in img.loads:
        p0, p1 = va & ~(PAGE - 1), (va + m + PAGE - 1) & ~(PAGE - 1)
        for pg in range(p0, p1, PAGE):
            perms[pg] = perms.get(pg, 0) | fl
        if fs:
            mem[va - lo:va - lo + fs] = img.data[off:off + fs]
        s, e = va - lo, va + m - lo
        defined[s:e] = _ones(e - s)
        if fl & 2:
            writable[s:e] = _ones(e - s)
    runs = []
    run_lo, run_hi, run_fl = None, None, None
    for pg in sorted(perms) + [None]:            # one mem_map per run of contiguous pages with one protection
        fl = perms.get(pg) if pg is not None else None
        if run_lo is not None and (pg != run_hi or fl != run_fl):
            prot = (_uc.UC_PROT_READ if run_fl & 4 else 0) | (_uc.UC_PROT_WRITE if run_fl & 2 else 0) | \
                   (_uc.UC_PROT_EXEC if run_fl & 1 else 0)
            runs.append((run_lo, run_hi, prot or _uc.UC_PROT_NONE))
            run_lo = None
        if pg is None:
            break
        if run_lo is None:
            run_lo, run_fl = pg, fl
        run_hi = pg + PAGE
    # executable pages: bytes no executable segment covers must never execute
    code_gaps = []
    for pg in sorted(perms):
        if not perms[pg] & 1:
            continue
        cover = [(max(va, pg), min(va + m, pg + PAGE)) for (va, m, _f, _o, fl) in img.loads
                 if fl & 1 and va < pg + PAGE and va + m > pg]
        cur = pg
        for (s, e) in sorted(cover):
            if s > cur:
                code_gaps.append((cur, s))
            cur = max(cur, e)
        if cur < pg + PAGE:
            code_gaps.append((cur, pg + PAGE))
    imports = {}
    ones8 = _ones(8)
    zero8 = bytes(8)
    for (off, kind, payload) in img.plan:
        o = off - lo
        if kind == "poison":
            defined[o:o + payload] = bytes(payload)
            continue
        if kind == "rel" or kind == "sym":
            val = (b + payload) & M64
        elif kind == "abs":
            val = payload
        elif kind == "trap":
            val = _layout_trap(L, payload)
        elif kind == "canary":
            # Mach-O (B-241): ___stack_chk_guard is a data symbol; its GOT slot points at the canary cell
            val = L["tls"] + L["tls_off"] + 0x28
        elif kind == "import":
            if payload not in imports:
                if len(imports) >= TRAP_COUNT - TRAP_IMPORT_BASE:
                    defined[o:o + 8] = zero8
                    continue
                imports[payload] = TRAP_IMPORT_BASE + len(imports)
            val = _layout_trap(L, imports[payload])
        else:
            raise EmulationError("unknown relocation plan kind")
        struct.pack_into("<Q", mem, o, val)
        defined[o:o + 8] = ones8
    relro = None
    if img.relro:                               # read-only after relocation, rounded out to whole pages (bionic)
        s = (img.relro[0] & ~(PAGE - 1))
        e = (img.relro[0] + img.relro[1] + PAGE - 1) & ~(PAGE - 1)
        s, e = max(s, lo), min(e, hi)
        if e > s:
            writable[s - lo:e - lo] = bytes(e - s)
            ex = any(fl & 1 and va < e and va + m > s for (va, m, _f, _o, fl) in img.loads)
            relro = (s, e, _uc.UC_PROT_READ | (_uc.UC_PROT_EXEC if ex else 0))
    # KB-2 fix round 2 (the review of 4250749, perf): the only non-zero bytes of the laid-out image are the file-backed
    # bytes of each PT_LOAD and the relocation slots; a fresh mapping is zero-filled, so a run writes those ranges and
    # nothing else (a 15 MiB .bss was written byte for byte into every run before)
    marks = sorted([(va, va + fs) for (va, _m, fs, _o, _fl) in img.loads if fs] +
                   [(off, off + 8) for (off, kind, _p) in img.plan if kind != "poison"])
    writes = []
    for (s0, e0) in marks:
        s0, e0 = max(s0, lo), min(e0, hi)
        if e0 <= s0:
            continue
        if writes and s0 <= writes[-1][1]:
            writes[-1] = (writes[-1][0], max(writes[-1][1], e0))
        else:
            writes.append((s0, e0))
    got = dict(img=img, runs=runs, mem=bytes(mem), defined=bytes(defined), writable=bytes(writable),
               code_gaps=code_gaps, import_names={v: k for k, v in imports.items()}, relro=relro, writes=writes)
    if hi - lo <= _LAID_MAX_SPAN:
        _LAID[key] = got
        _LAID_ORDER.append(key)
        while len(_LAID_ORDER) > _LAID_MAX:
            _LAID.pop(_LAID_ORDER.pop(0), None)
    return got


class _Run:
    """One emulation of one call, in one layout. Every failure raises EmulationError."""

    def __init__(self, img, layout_index, max_blocks, max_mem, classes=(), natives=()):
        if img.problem:
            raise SetupError(img.problem)
        try:
            self._setup(img, layout_index, max_blocks, max_mem, classes, natives)
        except _uc.UcError as e:                       # a mapping the layout cannot hold: a decline
            raise SetupError("the image cannot be laid out: %s" % e)

    def _setup(self, img, layout_index, max_blocks, max_mem, classes, natives):
        self.classes = frozenset(classes or ())   # internal names (a/b/C) FindClass may answer
        self.natives = frozenset(natives or ())   # (class, name, signature) of ACC_NATIVE methods
        self.phase = "call"                        # "load" while constructors / JNI_OnLoad run
        self.registered = {}                       # (class, name, signature) -> image vaddr (RegisterNatives)
        self.sinks = None                          # B-166: {"stdio", 1, 2: bytearray} once emulate_call captures output
        self.img = img
        self.L = L = _LAYOUTS[layout_index]
        self.fill = _POISON[layout_index]
        self.x86 = img.arch == ARCH_X86_64
        self.base = L["image"] if img.etype == ET_DYN else 0
        self.max_blocks, self.max_mem = max_blocks, max_mem
        self.blocks = 0
        self.mem = 0
        self.error = None
        self.error_cls = EmulationError            # BudgetError when the first failure was the work budget
        self.trap = None
        self.handles = {}
        self.ref_kind = {}          # handle -> "local" | "global" | "weak" (B-241)
        self.frames = []            # PushLocalFrame frames: the local handles created inside each, innermost last
        self.load_refs = frozenset()   # global / weak handles the load phase left: a call may not delete them
        self.monitors = {}          # id(object) -> MonitorEnter depth
        self.next_handle = 0
        self.heap_next = L["heap"] + L["heap_off"]
        self.blocks_live = {}       # heap block start -> size
        self.block_room = {}        # heap block start -> the bytes it may grow to in place (run B), its first size (A)
        self.block_first = {}       # heap block start -> the size it was first asked for (its size class)
        self.freed = []             # run B: freed blocks, oldest first (a device's allocator hands back the newest)
        self.frozen = set()         # heap blocks the load phase allocated: read-only during a call, never freed
        self.utf_out = {}           # pointer from GetStringUTFChars -> handle
        self.elems = {}             # pointer from Get<Prim>ArrayElements -> [handle, kind, n, original bytes]
        self.uc = uc = _uc.Uc(_uc.UC_ARCH_X86, _uc.UC_MODE_64) if self.x86 else _uc.Uc(_uc.UC_ARCH_ARM64, _uc.UC_MODE_ARM)
        self.regs = _ne._x86_regs() if self.x86 else _ne._arm64_regs()
        self.regions = []
        self._map_image(layout_index)
        self._map_runtime()
        self._install_hooks()

    # --------------------------------------------------------------- memory layout
    def _region(self, lo, hi, name):
        r = _Region(lo, hi, name)
        self.regions.append(r)
        self.regions.sort(key=lambda x: x.lo)
        return r

    def _map_image(self, layout_index):
        """Map the image as the loader leaves it after relocation (_laid_out: built once per image and layout,
        then written with one mem_write per run of pages), and protect RELRO."""
        img, b, uc = self.img, self.base, self.uc
        lo, hi = img.lo, img.hi
        st = _laid_out(img, layout_index)
        self.rimg = r = self._region(b + lo, b + hi, "image")
        for (run_lo, run_hi, prot) in st["runs"]:
            uc.mem_map(b + run_lo, run_hi - run_lo, prot)
        mem = st["mem"]
        for (w_lo, w_hi) in st["writes"]:              # every other byte of a fresh mapping is already the zero it holds
            uc.mem_write(b + w_lo, mem[w_lo - lo:w_hi - lo])
        r.defined[:] = st["defined"]
        r.writable[:] = st["writable"]
        self.code_gaps = [(b + s, b + e) for (s, e) in st["code_gaps"]]
        self.import_names = st["import_names"]
        if st["relro"] is not None:
            s, e, prot = st["relro"]
            try:
                uc.mem_protect(b + s, e - s, prot)
            except Exception:
                pass
        # snapshot of the writable image bytes, to detect state that escapes a call (retaken after a load phase)
        self.rw_ranges = [(b + va, b + va + m) for (va, m, _f, _o, fl) in img.loads if fl & 2]
        self.rw_before = [st["mem"][s - b - lo:e - b - lo] for (s, e) in self.rw_ranges]
        self.rw_def_before = [st["defined"][s - b - lo:e - b - lo] for (s, e) in self.rw_ranges]

    def _map_runtime(self):
        L, uc = self.L, self.uc
        # stack
        st_lo = L["stack"] - STACK_SIZE
        uc.mem_map(st_lo, STACK_SIZE, _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
        self.rstack = rs = self._region(st_lo, L["stack"], "stack")
        rs.writable[:] = _ones(STACK_SIZE) if STACK_SIZE < len(_ONES) else b"\x01" * STACK_SIZE
        # heap (writable only inside live blocks)
        uc.mem_map(L["heap"], HEAP_SIZE, _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
        self.rheap = self._region(L["heap"], L["heap"] + HEAP_SIZE, "heap")
        # TLS: only the stack-protector slot is defined
        uc.mem_map(L["tls"], PAGE, _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
        self.rtls = rt = self._region(L["tls"], L["tls"] + PAGE, "tls")
        rt.writable[:] = b"\x01" * PAGE
        uc.mem_write(L["tls"] + L["tls_off"] + 0x28, struct.pack("<Q", L["canary"]))
        rt.defined[L["tls_off"] + 0x28:L["tls_off"] + 0x30] = _ones(8)
        tls0 = bytearray(PAGE)
        tls0[L["tls_off"] + 0x28:L["tls_off"] + 0x30] = struct.pack("<Q", L["canary"])
        self.tls_before = (bytes(tls0), bytes(rt.defined))   # retaken after a load phase (_seal_load)
        # JNIEnv and JavaVM (read-only, two pages). Page 0: the JNIEnv (a pointer to its function table) at env_off,
        # the JavaVM JNI_OnLoad receives (a pointer to its JNIInvokeInterface table) at vm_off and that table at
        # vt_off; page 1: the JNI function table at table_off. Every table slot is a trap address.
        uc.mem_map(L["jni"], 2 * PAGE, _uc.UC_PROT_READ)
        rj = self._region(L["jni"], L["jni"] + 2 * PAGE, "jni")
        self.env = L["jni"] + L["env_off"]
        table = L["jni"] + PAGE + L["table_off"]
        uc.mem_write(self.env, struct.pack("<Q", table))
        # GetModule (slot 233, JNI >= 9) is left UNDEFINED, not a trap: whether a device's ART carries it depends on
        # the API level, which the image does not fix, so a native that reads it must decline rather than agree in
        # both runs. Only slots 0..GetObjectRefType (232) are defined; reserved0..3 are NULL, every other a trap.
        ndef = len(JNI_SLOTS) - 1
        uc.mem_write(table, b"".join(struct.pack("<Q", 0 if (i < 4 or i >= ndef) else self.trap_addr(TRAP_JNI_BASE + i))
                                     for i in range(len(JNI_SLOTS))))
        rj.defined[L["env_off"]:L["env_off"] + 8] = _ones(8)
        t0 = PAGE + L["table_off"]
        rj.defined[t0:t0 + 8 * ndef] = b"\x01" * (8 * ndef)
        self.vm_ptr = L["jni"] + L["vm_off"]
        vtable = L["jni"] + L["vt_off"]
        uc.mem_write(self.vm_ptr, struct.pack("<Q", vtable))
        uc.mem_write(vtable, b"".join(struct.pack("<Q", 0 if i < 3 else self.trap_addr(TRAP_VM_BASE + i))
                                      for i in range(len(VM_SLOTS))))
        rj.defined[L["vm_off"]:L["vm_off"] + 8] = _ones(8)
        rj.defined[L["vt_off"]:L["vt_off"] + 8 * len(VM_SLOTS)] = _ones(8 * len(VM_SLOTS))
        # traps: executable, never readable as data (no region), filled with an undefined instruction; the first
        # trap sits trap_off into the mapping (an entry before it executes the fill and faults)
        nbytes = L["trap_off"] + TRAP_COUNT * L["trap_step"]
        size = (nbytes + PAGE - 1) & ~(PAGE - 1)
        uc.mem_map(L["trap"], size, _uc.UC_PROT_READ | _uc.UC_PROT_EXEC)
        fillw = b"\x0f\x0b" if self.x86 else struct.pack("<I", 0xD4200000)
        uc.mem_write(L["trap"], fillw * (size // len(fillw)))
        if self.x86:
            uc.reg_write(_x86c.UC_X86_REG_FS_BASE, L["tls"] + L["tls_off"])
            # a Linux user thread's fixed state (the kernel's and the ABI's): selectors, MXCSR, the x87 control word
            uc.reg_write(_x86c.UC_X86_REG_CS, 0x33)
            uc.reg_write(_x86c.UC_X86_REG_SS, 0x2B)
            uc.reg_write(_x86c.UC_X86_REG_MXCSR, 0x1F80)
            uc.reg_write(_x86c.UC_X86_REG_FPCW, 0x037F)
        else:
            uc.reg_write(_a64c.UC_ARM64_REG_TPIDR_EL0, L["tls"] + L["tls_off"])

    def trap_addr(self, tid):
        return _layout_trap(self.L, tid)

    # --------------------------------------------------------------- shadow helpers
    def find(self, addr):
        for r in self.regions:
            if r.lo <= addr < r.hi:
                return r
        return None

    def check_read(self, addr, n):
        r = self.find(addr)
        if r is None or addr + n > r.hi:
            raise EmulationError("read of unmapped/foreign memory @%#x" % addr)
        o = addr - r.lo
        if r.defined[o:o + n] != _ones(n):
            raise EmulationError("read of undefined memory @%#x (%s)" % (addr, r.name))
        return r

    def check_write(self, addr, n):
        r = self.find(addr)
        if r is None or addr + n > r.hi:
            raise EmulationError("write to unmapped/foreign memory @%#x" % addr)
        o = addr - r.lo
        if r.writable[o:o + n] != _ones(n):
            raise EmulationError("write to non-writable memory @%#x (%s)" % (addr, r.name))
        return r

    def _raw(self, addr, n):
        try:
            return bytes(self.uc.mem_read(addr, n))
        except Exception:
            raise EmulationError("read of unmapped memory @%#x" % addr)

    def read(self, addr, n):
        if n == 0:
            return b""
        self.check_read(addr, n)
        return self._raw(addr, n)

    def write(self, addr, data, defined=None):
        n = len(data)
        if n == 0:
            return
        r = self.check_write(addr, n)
        self.uc.mem_write(addr, bytes(data))
        o = addr - r.lo
        r.defined[o:o + n] = _ones(n) if defined is None else defined

    def read_shadow(self, addr, n):
        """(bytes, definedness) of n bytes in ONE region (undefined bytes allowed), for memcpy/memmove."""
        r = self.find(addr)
        if r is None or addr + n > r.hi:
            raise EmulationError("copy from unmapped/foreign memory @%#x" % addr)
        o = addr - r.lo
        dd = bytes(r.defined[o:o + n])
        if dd == _ones(n):
            return self._raw(addr, n), dd
        out = bytearray(n)                  # undefined bytes may sit in unmapped holes: read page by page
        a = addr
        while a < addr + n:
            e = min(addr + n, (a | (PAGE - 1)) + 1)
            if r.defined[a - r.lo:e - r.lo].count(1):
                out[a - addr:e - addr] = self._raw(a, e - a)
            a = e
        return bytes(out), dd

    def cstr(self, addr, limit=MAX_STR):
        r = self.find(addr)
        if r is None:
            raise EmulationError("string at unmapped/foreign memory @%#x" % addr)
        out = bytearray()
        a = addr
        while True:
            if a >= r.hi:
                raise EmulationError("string runs off its region")
            chunk_end = min(r.hi, (a | (PAGE - 1)) + 1, a + 256)
            self.check_read(a, 1)
            self._charge(chunk_end - a)
            raw = self._raw(a, chunk_end - a)
            o = a - r.lo
            dd = r.defined[o:o + len(raw)]
            z = raw.find(b"\x00")
            upto = len(raw) if z < 0 else z + 1
            if dd[:upto] != _ones(upto):
                raise EmulationError("string reads undefined memory @%#x" % a)
            if z >= 0:
                out += raw[:z]
                break
            out += raw
            a = chunk_end
            if len(out) > limit:
                raise EmulationError("string longer than %d bytes" % limit)
        return bytes(out)

    # --------------------------------------------------------------- heap
    def malloc(self, n, zero=False, size_zero_choice=False):
        if n == 0 and size_zero_choice:
            # malloc(0)/calloc(0) is implementation-defined (NULL or a unique pointer): run A answers NULL, run
            # B a unique zero-byte block, so a caller whose result depends on which one declines.
            if self.L["iscopy"]:
                return 0
            p = self.malloc(1)
            self.rheap.writable[p - self.rheap.lo] = 0
            return p
        if n <= 0 or n > HEAP_SIZE:
            raise EmulationError("malloc(%d) not modelled" % n)
        r = self.rheap
        start = self._reuse(n) if self.L["heap_classes"] else None
        if start is None:
            room = _heap_room(n) if self.L["heap_classes"] else n
            start = (self.heap_next + 15) & ~15
            end = start + room
            if end > r.hi:
                raise EmulationError("bounded heap exhausted")
            self.heap_next = end + self.L["heap_gap"]  # a red zone: never writable (its size differs per layout)
            self.block_room[start] = room
            self.block_first[start] = n
        o = start - r.lo
        r.writable[o:o + n] = _ones(n) if n < len(_ONES) else b"\x01" * n
        if zero:
            self.uc.mem_write(start, bytes(n))
            r.defined[o:o + n] = r.writable[o:o + n]
        self.blocks_live[start] = n
        return start

    def _reuse(self, n):
        """Run B: the most recently freed block a device's allocator hands back for an `n`-byte request (the newest
        freed block of its size class), or None. When the newest freed block that some allocator might hand back is
        one that another would not (sizes neither surely in one class nor surely in two), it declines: which block
        comes back is the allocator's choice. The scan is charged to the work budget."""
        for k in range(len(self.freed) - 1, -1, -1):
            self._charge(64)
            q = self.freed[k]
            first = self.block_first[q]
            if _heap_apart(first, n):
                continue
            if not _heap_same(first, n):
                raise EmulationError("malloc(%d) after a free of a block first asked for %d bytes: whether a device's "
                                     "allocator hands that block back is the allocator's choice" % (n, first))
            del self.freed[k]
            return q
        return None

    def free(self, p):
        if p == 0:
            return
        if p in self.frozen:
            raise EmulationError("free of a block the load phase allocated (state escapes the call)")
        n = self.blocks_live.pop(p, None)
        if n is None:
            raise EmulationError("free of a pointer that is not a live heap block")
        r = self.rheap
        o = p - r.lo
        r.writable[o:o + n] = bytes(n)
        r.defined[o:o + n] = bytes(n)
        if self.L["heap_classes"]:
            self.freed.append(p)

    # --------------------------------------------------------------- hooks
    def _install_hooks(self):
        uc = self.uc

        def fail(msg, cls=EmulationError):
            if self.error is None:
                self.error = msg
                self.error_cls = cls
            uc.emu_stop()

        def h_read(uc_, access, address, size, value, _u):
            self.mem += 1
            if self.mem > self.max_mem:
                fail("memory-access budget exceeded", BudgetError)
                return
            r = self.find(address)
            if r is None or address + size > r.hi:
                fail("read of memory outside every modelled region @%#x" % address)
                return
            o = address - r.lo
            if r.defined[o:o + size] != _ones(size):
                fail("read of undefined memory @%#x (%s)" % (address, r.name))

        def h_write(uc_, access, address, size, value, _u):
            self.mem += 1
            if self.mem > self.max_mem:
                fail("memory-access budget exceeded", BudgetError)
                return
            r = self.find(address)
            if r is None or address + size > r.hi:
                fail("write outside every modelled region @%#x" % address)
                return
            o = address - r.lo
            if r.writable[o:o + size] != _ones(size):
                fail("write to non-writable memory @%#x (%s)" % (address, r.name))
                return
            r.defined[o:o + size] = _ones(size)

        def h_bad(uc_, access, address, size, value, _u):
            kind = {_uc.UC_MEM_READ_UNMAPPED: "read of unmapped", _uc.UC_MEM_WRITE_UNMAPPED: "write to unmapped",
                    _uc.UC_MEM_FETCH_UNMAPPED: "fetch from unmapped", _uc.UC_MEM_WRITE_PROT: "write to protected",
                    _uc.UC_MEM_READ_PROT: "read of protected", _uc.UC_MEM_FETCH_PROT: "fetch from non-executable"
                    }.get(access, "invalid access to")
            fail("%s memory @%#x" % (kind, address))
            return False

        scan = self.img.__dict__.setdefault("_x86_scan", {}) if self.x86 else None
        rimg = self.rimg

        def h_block(uc_, address, size, _u):
            self.blocks += 1
            if self.blocks > self.max_blocks:
                fail("block budget exceeded", BudgetError)
                return
            if scan is not None and rimg.lo <= address < rimg.hi:
                k = (address - self.base, size)
                bad = scan.get(k)
                if bad is None:
                    bad = _x86_block_problem(bytes(uc_.mem_read(address, size)))
                    if len(scan) > 65536:
                        scan.clear()
                    scan[k] = bad
                if bad:
                    fail("%s executed (its value depends on the machine, not on the bytes)" % bad)

        def h_sysreg(uc_, reg, cp, _u):
            key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2)
            if key not in _A64_MRS_OK:
                fail("system register %s read (its value depends on the machine)" % (key,))
                return True
            return False

        def h_sysreg_w(uc_, reg, cp, _u):
            key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2)
            if key not in _A64_MSR_OK:
                fail("system register %s written (not modelled)" % (key,))
                return True
            return False

        def h_sys(uc_, reg, cp, _u):
            fail("a system instruction (SYS/SYSL) executed (not modelled)")
            return True

        def h_trap(uc_, address, size, _u):
            self.trap = address
            uc_.emu_stop()

        def h_gap(uc_, address, size, _u):
            fail("execution outside the image's code @%#x" % address)

        def h_intr(uc_, intno, _u):
            fail("software interrupt / syscall denied")

        def h_syscall(uc_, _u):
            fail("syscall denied")

        self._hooks = (h_read, h_write, h_bad, h_block, h_trap, h_gap, h_intr, h_syscall, h_sysreg, h_sysreg_w,
                       h_sys)   # keep refs
        if not self.x86:
            for ins, cb in ((_a64c.UC_ARM64_INS_MRS, h_sysreg), (_a64c.UC_ARM64_INS_MSR, h_sysreg_w),
                            (_a64c.UC_ARM64_INS_SYS, h_sys), (_a64c.UC_ARM64_INS_SYSL, h_sys)):
                uc.hook_add(_uc.UC_HOOK_INSN, cb, None, 1, 0, ins)
        elif _CS_X86 is None:
            raise SetupError("capstone is not available to vet x86 blocks")
        uc.hook_add(_uc.UC_HOOK_MEM_READ, h_read)
        uc.hook_add(_uc.UC_HOOK_MEM_WRITE, h_write)
        uc.hook_add(_uc.UC_HOOK_MEM_UNMAPPED | _uc.UC_HOOK_MEM_PROT, h_bad)
        uc.hook_add(_uc.UC_HOOK_BLOCK, h_block)
        t0 = self.L["trap"] + self.L["trap_off"]
        uc.hook_add(_uc.UC_HOOK_CODE, h_trap, begin=t0, end=t0 + self.L["trap_step"] * TRAP_COUNT - 1)
        for (s, e) in self.code_gaps:
            uc.hook_add(_uc.UC_HOOK_CODE, h_gap, begin=s, end=e - 1)
        uc.hook_add(_uc.UC_HOOK_INTR, h_intr)
        if self.x86:
            for name in ("UC_X86_INS_SYSCALL", "UC_X86_INS_SYSENTER"):
                try:
                    uc.hook_add(_uc.UC_HOOK_INSN, h_syscall, begin=1, end=0, aux1=getattr(_x86c, name))
                except Exception:
                    pass

    # --------------------------------------------------------------- registers
    def rr(self, name):
        return self.uc.reg_read(self.regs[name]) & M64

    def rw(self, name, v):
        self.uc.reg_write(self.regs[name], v & M64)

    def _poison_regs(self, names):
        for n in names:
            self.rw(n, self.fill)

    def _clobber(self, keep_result):
        """After a modelled call: caller-saved registers and the flags become undefined (poison)."""
        uc = self.uc
        if self.x86:
            self._poison_regs([n for n in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
                               if not (keep_result and n == "rax")])
            uc.reg_write(_x86c.UC_X86_REG_EFLAGS, self.L["flags_x86"] | 0x202)   # IF and bit 1, as in user mode
            uc.reg_write(_x86c.UC_X86_REG_MXCSR, 0x1F80)
            wide = (self.fill << 64) | self.fill
            for i in range(16):
                uc.reg_write(getattr(_x86c, "UC_X86_REG_XMM%d" % i), wide)
        else:
            self._poison_regs(["x%d" % i for i in range(0 if not keep_result else 1, 18)])
            uc.reg_write(_a64c.UC_ARM64_REG_NZCV, self.L["nzcv"])
            wide = (self.fill << 64) | self.fill
            for i in list(range(0, 8)) + list(range(16, 32)):
                uc.reg_write(getattr(_a64c, "UC_ARM64_REG_V%d" % i), wide)

    # --------------------------------------------------------------- handles
    def new_handle(self, obj, kind="local"):
        """A new JNI reference to `obj`. In the layout that carries ART's kind bits a global reference ends in
        binary 10 and a weak one in 11, as ART's do (a local one in 01); the other layout carries none."""
        self.next_handle += 1
        h = self.L["handle"] + self.L["handle_step"] * self.next_handle
        if self.L["handle"] & 3 == 1 and kind != "local":
            h += 1 if kind == "global" else 2
        self.handles[h] = obj
        self.ref_kind[h] = kind
        if kind == "local" and self.frames:
            self.frames[-1].add(h)
        return h

    def drop_handle(self, h):
        del self.handles[h]
        del self.ref_kind[h]
        for frame in self.frames:
            frame.discard(h)

    def strong(self, h, what):
        """The object behind reference `h` for a call that creates a new reference to it: a live local or
        global reference, or a weak one whose object some other live strong reference still holds (otherwise
        the collector decides whether it is there)."""
        h &= M64
        o = self.handles.get(h)
        if o is None:
            raise EmulationError("%s of a reference that is not a live handle" % what)
        if self.ref_kind[h] == "weak" and not any(
                self.handles[k] is o and self.ref_kind[k] != "weak" for k in self.handles):
            raise EmulationError("%s of a weak global reference whose object nothing else holds (the collector "
                                 "decides whether it is still there)" % what)
        return o

    def obj(self, h, want=None):
        o = self.handles.get(h & M64)
        if o is None:
            raise EmulationError("JNI call with a reference that is not a live handle")
        if self.ref_kind.get(h & M64) == "weak":
            raise EmulationError("JNI call with a weak global reference (it must be promoted with NewLocalRef "
                                 "first)")
        if want is JStr and not isinstance(o, JStr):
            raise EmulationError("JNI string call on a non-string reference")
        if want is JArr and not isinstance(o, JArr):
            raise EmulationError("JNI array call on a non-array reference")
        if want is JClass and not isinstance(o, JClass):
            raise EmulationError("JNI class call on a reference that is not a class FindClass returned")
        return o

    # --------------------------------------------------------------- the call
    def call(self, entry, args, absolute=False, check_state=True, ret_fp=None):
        """Run the function at image vaddr `entry` (a run address with `absolute`) with `args` [(value, bits)]
        (bits 32 or 64: a 32-bit argument carries poison in its upper half; bits "F" or "D": a float or double
        given as its IEEE bit pattern, passed in the next vector register with poison above it) and return the
        raw 64-bit return register, or with `ret_fp` ("F" / "D") the low 32 / 64 bits of the first vector
        register. `check_state` (the default; off only for the load phase) declines a call that left the
        image's writable memory changed."""
        fp_args = [(v, bits) for (v, bits) in args if bits in ("F", "D")]
        args = [(v, bits) for (v, bits) in args if bits not in ("F", "D")]
        if len(fp_args) > 8:
            raise SetupError("more than 8 floating-point arguments (stack-passed ones are not modelled)")
        uc, L = self.uc, self.L
        b = self.base
        pc = entry if absolute else b + entry
        r = self.find(pc)
        if r is not self.rimg or not self.img._in_exec(pc - b):
            raise (EmulationError if absolute else SetupError)("entry %#x is not inside the image's code" % (pc - b))
        sentinel = self.trap_addr(TRAP_SENTINEL)
        top = L["stack"] - L["stack_gap"]          # 16-aligned, different in bits 4-11 between the layouts
        hi_fill = self.fill & ~M32
        # every call starts with an UNDEFINED stack: what an earlier call of the run (a constructor, JNI_OnLoad)
        # left there is not what a device's stack holds at this call, so reading it must decline
        self.rstack.defined[:] = bytes(len(self.rstack.defined))

        def argval(v, bits):
            return (v & M64) if bits == 64 else ((v & M32) | hi_fill)
        gpr = ("rdi", "rsi", "rdx", "rcx", "r8", "r9") if self.x86 else tuple("x%d" % i for i in range(8))
        # every general register undefined first, then the arguments
        if self.x86:
            self._poison_regs(("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11",
                               "r12", "r13", "r14", "r15"))
            uc.reg_write(_x86c.UC_X86_REG_EFLAGS, L["flags_x86"] | 0x202)       # IF and bit 1, as in user mode
            uc.reg_write(_x86c.UC_X86_REG_MXCSR, 0x1F80)
            uc.reg_write(_x86c.UC_X86_REG_FPCW, 0x037F)
        else:
            self._poison_regs(["x%d" % i for i in range(31)])
            uc.reg_write(_a64c.UC_ARM64_REG_NZCV, L["nzcv"])
        wide = (self.fill << 64) | self.fill
        for i in range(16 if self.x86 else 32):
            uc.reg_write(getattr(_x86c, "UC_X86_REG_XMM%d" % i) if self.x86 else getattr(_a64c, "UC_ARM64_REG_V%d" % i),
                         wide)
        for i, (v, bits) in enumerate(fp_args):
            # the ABI defines only the value's own bits: everything above them in the register is the caller's
            # leftover, so it is poison here
            low = (1 << (32 if bits == "F" else 64)) - 1
            uc.reg_write(getattr(_x86c, "UC_X86_REG_XMM%d" % i) if self.x86 else getattr(_a64c, "UC_ARM64_REG_V%d" % i),
                         (wide & ~low) | (v & low))
        reg_args, stack_args = args[:len(gpr)], args[len(gpr):]
        for name, (v, bits) in zip(gpr, reg_args):
            self.rw(name, argval(v, bits))
        if len(stack_args) > 16:
            raise SetupError("more than 16 stack arguments")
        sp = top - 8 * len(stack_args)
        sp &= ~0xF
        for k, (v, bits) in enumerate(stack_args):
            self.write(sp + 8 * k, struct.pack("<Q", argval(v, bits)))
        if self.x86:
            sp -= 8
            self.write(sp, struct.pack("<Q", sentinel))
            self.rw("rsp", sp)
        else:
            self.rw("sp", sp)
            self.rw("lr", sentinel)
        while True:
            self.trap = None
            try:
                uc.emu_start(pc, 0, 0, 0)
            except _uc.UcError as e:
                if self.error is None:
                    self.error = "emulation fault: %s" % e
            if self.error:
                raise self.error_cls(self.error)
            if self.trap is None:
                raise EmulationError("emulation stopped without returning")
            tid = _trap_id(self.L, self.trap)
            if tid is None:
                raise EmulationError("jump into the middle of a trap")
            if tid == TRAP_SENTINEL:
                if self.x86 and self.rr("rsp") != sp + 8:
                    raise EmulationError("returned with an unbalanced stack")
                if (not self.x86) and self.rr("sp") != sp:
                    raise EmulationError("returned with an unbalanced stack")
                if ret_fp:
                    vec = uc.reg_read(_x86c.UC_X86_REG_XMM0 if self.x86 else _a64c.UC_ARM64_REG_V0)
                    ret = vec & ((1 << (32 if ret_fp == "F" else 64)) - 1)
                else:
                    ret = self.rr("rax" if self.x86 else "x0")
                if check_state:
                    self._check_state()
                return ret
            pc = self._service(tid)

    # --------------------------------------------------------------- the load phase
    def load(self, jni):
        """Run what the loader runs before any call: the constructors (DT_INIT, DT_INIT_ARRAY) and, with `jni`,
        the exported JNI_OnLoad as ART calls it from System.loadLibrary (JavaVM*, NULL), which must return a
        version ART accepts. The writable-memory snapshot that _check_state compares against is retaken after
        it, so a call starts from the loaded state. Every failure declines (EmulationError)."""
        img = self.img
        if img.section_constructors():
            raise EmulationError("a static image's constructor table is not modelled")
        ctors = img.constructors()
        onload = img.exports().get("JNI_OnLoad") if jni else None
        if not ctors and onload is None:
            return None
        self.phase = "load"
        poison3 = [(self.fill, 64)] * 3            # argc, argv, envp: undefined to the model
        for kind, va in ctors:
            if kind == "func":
                self.call(va, poison3, check_state=False)
                continue
            fn = struct.unpack("<Q", self.read(self.base + va, 8))[0]
            if fn in (0, M64):                       # bionic and glibc skip 0 and -1 slots
                continue
            self.call(fn, poison3, absolute=True, check_state=False)
        version = None
        if onload is not None:
            raw = self.call(onload, [(self.vm_ptr, 64), (0, 64)], check_state=False)
            version = raw & M32
            if version not in JNI_VERSIONS_ONLOAD:
                raise EmulationError("JNI_OnLoad returned %#x, a version ART refuses (the load fails)" % version)
        self.phase = "call"
        if self.utf_out or self.elems:
            raise EmulationError("the load phase kept a JNI buffer it never released")
        if any(self.monitors.values()):
            raise EmulationError("the load phase returned holding a JNI monitor")
        self._seal_load()
        return version

    def _seal_load(self):
        """The loaded state every call starts from (each run loads afresh, so a call never sees what an earlier
        call left): what the load phase put in the image's writable segments, in TLS and in the heap blocks it
        allocated is snapshotted, and _check_state declines a call that changes any of it (on a device the next
        call would see the change: a malloc'd counter, a rolling cipher state). The load phase's heap blocks become
        read-only (a write declines at once) and can never be freed or reallocated; its JNI local references are
        gone, as ART frees them when JNI_OnLoad returns, so a call that uses one declines. Its global and weak
        global references live on (B-241): a call may use them and may not delete them."""
        r = self.rimg
        self.rw_before = [bytes(self.uc.mem_read(s, e - s)) for (s, e) in self.rw_ranges]
        self.rw_def_before = [bytes(r.defined[s - r.lo:e - r.lo]) for (s, e) in self.rw_ranges]
        rt = self.rtls
        self.tls_before = (bytes(self.uc.mem_read(rt.lo, rt.hi - rt.lo)), bytes(rt.defined))
        rh = self.rheap
        for p, n in self.blocks_live.items():
            rh.writable[p - rh.lo:p - rh.lo + n] = bytes(n)
            self.frozen.add(p)
        for h in [h for h, kind in self.ref_kind.items() if kind == "local"]:
            del self.handles[h]
            del self.ref_kind[h]
        self.frames = []                               # ART pops every local frame when the native returns
        self.load_refs = frozenset(self.handles)

    def _check_state(self):
        """Decline when the call left the image's writable memory or TLS changed (state escaping the call). The
        load phase's heap blocks need no check: they are read-only during a call."""
        r = self.rimg
        for (s, e), before, dbefore in zip(self.rw_ranges, self.rw_before, self.rw_def_before):
            now = bytes(self.uc.mem_read(s, e - s))
            dnow = bytes(r.defined[s - r.lo:e - r.lo])
            if now != before or dnow != dbefore:
                raise EmulationError("the call changed the image's writable memory (state escapes the call)")
        rt, tb = self.rtls, self.tls_before
        if bytes(self.uc.mem_read(rt.lo, rt.hi - rt.lo)) != tb[0] or bytes(rt.defined) != tb[1]:
            raise EmulationError("the call changed thread-local storage (state escapes the call)")

    def _ret_addr(self):
        if self.x86:
            sp = self.rr("rsp")
            ra = struct.unpack("<Q", self.read(sp, 8))[0]
            self.rw("rsp", sp + 8)
            return ra
        return self.rr("lr")

    def _args(self, n):
        names = ("rdi", "rsi", "rdx", "rcx", "r8", "r9") if self.x86 else tuple("x%d" % i for i in range(8))
        if n > len(names):
            raise EmulationError("modelled call with stack arguments")
        return [self.rr(names[i]) for i in range(n)]

    def _service(self, tid):
        """Perform the modelled function `tid` and return the address to resume at."""
        if TRAP_VM_BASE <= tid < TRAP_VM_BASE + len(VM_SLOTS):
            res, kind = self._vm(VM_SLOTS[tid - TRAP_VM_BASE])
        elif 1 <= tid < TRAP_VM_BASE:
            name = LIBC_FUNCS[tid - 1] if tid - 1 < len(LIBC_FUNCS) else None
            if name is None:
                raise EmulationError("call into an unassigned trap")
            res, kind = self._libc(name)
        elif tid < TRAP_JNI_BASE:
            raise EmulationError("call into an unassigned trap")
        elif TRAP_JNI_BASE <= tid < TRAP_IMPORT_BASE:
            idx = tid - TRAP_JNI_BASE
            name = JNI_SLOTS[idx] if idx < len(JNI_SLOTS) else "slot%d" % idx
            if name not in JNI_MODELLED:
                raise EmulationError("JNI function %s is not modelled" % name)
            res, kind = self._jni(name)
        else:
            name = self.import_names.get(tid, "?")
            if self.sinks is None or name not in SINK_FUNCS:     # emulate_call sets sinks after the load phase
                raise EmulationError("call to unresolved import %s" % name)
            res, kind = self._sink(name)
        ra = self._ret_addr()
        self._clobber(keep_result=kind != "void")
        rreg = "rax" if self.x86 else "x0"
        if kind == "ptr":
            self.rw(rreg, res)
        elif kind == "int":
            self.rw(rreg, (res & M32) | (self.fill & ~M32))
        elif kind == "bool":
            self.rw(rreg, (res & 0xFF) | (self.fill & ~0xFF))
        return ra

    # --------------------------------------------------------------- libc models
    def _overlap(self, a, b, n):
        return n and a < b + n and b < a + n

    def _charge(self, n):
        """Count the work a model does (bytes copied, set, compared, scanned) against the run's memory-access
        budget, one access per 64 bytes and one per call, as the emulated code's own accesses count: a native
        that loops a large memcpy declines by its budget instead of spending seconds inside the model."""
        self.mem += 1 + (max(n, 0) >> 6)
        if self.mem > self.max_mem:
            raise BudgetError("memory-access budget exceeded (work inside a modelled library function)")

    def _libc(self, name):
        if name == "__stack_chk_fail":
            raise EmulationError("__stack_chk_fail: the stack canary was overwritten")
        if name in ("strlen", "__strlen_chk"):
            a = self._args(2)
            n = len(self.cstr(a[0]))
            if name == "__strlen_chk" and n >= a[1]:
                raise EmulationError("__strlen_chk would abort")
            return n, "ptr"
        if name in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk"):
            d, s, n, dl = self._args(4)
            if n > MAX_COPY:
                raise EmulationError("copy too long")
            if name.endswith("_chk") and n > dl:
                raise EmulationError("%s would abort" % name)
            if "memcpy" in name and self._overlap(d, s, n):
                raise EmulationError("memcpy of overlapping blocks (undefined behaviour)")
            self._charge(2 * n)
            if n:
                data, dd = self.read_shadow(s, n)
                self.write(d, data, dd)
            return d, "ptr"
        if name in ("memset", "__memset_chk"):
            d, c, n, dl = self._args(4)
            if n > MAX_COPY or (name == "__memset_chk" and n > dl):
                raise EmulationError("memset not modelled for this length")
            self._charge(n)
            if n:
                self.write(d, bytes([c & 0xFF]) * n)
            return d, "ptr"
        if name == "memcmp":
            a, b, n = self._args(3)
            if n > MAX_COPY:
                raise EmulationError("compare too long")
            self._charge(2 * n)
            x, y = self.read(a, n), self.read(b, n)
            return self._cmp(x, y), "int"
        if name in ("strcmp", "strncmp"):
            a, b, n = self._args(3)
            lim = MAX_STR if name == "strcmp" else min(n, MAX_STR)
            x, y = self._cmp_strs(a, b, lim)
            return self._cmp(x, y), "int"
        if name in ("strcpy", "__strcpy_chk"):
            d, s, dl = self._args(3)
            src = self.cstr(s) + b"\x00"
            if name == "__strcpy_chk" and len(src) > dl:
                raise EmulationError("__strcpy_chk would abort")
            if self._overlap(d, s, len(src)):
                raise EmulationError("strcpy of overlapping strings")
            self.write(d, src)
            return d, "ptr"
        if name in ("strncpy", "__strncpy_chk"):
            d, s, n, dl = self._args(4)
            if n > MAX_COPY or (name == "__strncpy_chk" and n > dl):
                raise EmulationError("strncpy not modelled for this length")
            self._charge(n)
            src = self._strn(s, n)
            out = src + bytes(n - len(src))
            if self._overlap(d, s, max(len(src), 1)) and n:
                raise EmulationError("strncpy of overlapping strings")
            if n:
                self.write(d, out)
            return d, "ptr"
        if name in ("strchr", "__strchr_chk"):
            s, c, sl = self._args(3)
            raw = self.cstr(s)
            ch = c & 0xFF
            pos = len(raw) if ch == 0 else raw.find(bytes([ch]))
            if name == "__strchr_chk" and (pos if pos >= 0 else len(raw)) >= sl:
                raise EmulationError("__strchr_chk would abort")
            return (s + pos) if pos >= 0 else 0, "ptr"
        if name == "malloc":
            (n,) = self._args(1)
            return self.malloc(n, size_zero_choice=True), "ptr"
        if name == "calloc":
            k, n = self._args(2)
            if k and n and k * n > HEAP_SIZE:
                raise EmulationError("calloc too large")
            self._charge(k * n)
            return self.malloc(k * n, zero=True, size_zero_choice=True), "ptr"
        if name == "realloc":
            p, n = self._args(2)
            if p == 0:
                return self.malloc(n), "ptr"
            old = self.blocks_live.get(p)
            if old is None or n == 0 or p in self.frozen:
                raise EmulationError("realloc not modelled for this pointer/size")
            if self.L["heap_classes"] and n <= self.block_room[p]:
                # run B keeps the block when the new size fits its room, run A always moves it: a device's allocator
                # keeps a block its new size still fits, so a result that depends on whether it moved declines
                r = self.rheap
                o = p - r.lo
                if n < old:
                    r.writable[o + n:o + old] = bytes(old - n)
                    r.defined[o + n:o + old] = bytes(old - n)
                elif n > old:
                    r.writable[o + old:o + n] = b"\x01" * (n - old)
                self.blocks_live[p] = n
                return p, "ptr"
            q = self.malloc(n)
            k = min(old, n)
            self._charge(k)
            data, dd = self.read_shadow(p, k)
            self.write(q, data, dd)
            self.free(p)
            return q, "ptr"
        if name == "free":
            (p,) = self._args(1)
            self.free(p)
            return 0, "void"
        if name == "__cxa_atexit":
            # registers a destructor that runs only at exit / dlclose, never during a call: success (0)
            return 0, "int"
        if name in ("__android_log_print", "__android_log_write", "__android_log_vprint"):
            # liblog writes the line to the device log: nothing the program can read back. It reads its tag (NULL
            # is the default tag) and its text or format as C strings (undefined bytes decline; a NULL text is not
            # modelled); the varargs are not read. Its result is the device's (1, or -EPERM below the log level):
            # the layouts answer 1 and -1, so a program that depends on it declines.
            _prio, tag, text = self._args(3)
            if tag:
                self.cstr(tag, 4096)
            if not text:
                raise EmulationError("%s with a NULL text is not modelled" % name)
            self.cstr(text, 4096)
            return self.L["log_ret"], "int"
        raise EmulationError("libc function %s is not modelled" % name)

    # --------------------------------------------------------------- output sinks (B-166, emulate_call only)
    def _emit(self, stream, data):
        """Append `data` to one captured output stream: "stdio" (stdout through the C library's buffer) or
        the file descriptor 1 / 2 (write(2), unbuffered). More than MAX_OUTPUT bytes in all declines (that
        bounds the work too; the strings were read through cstr, which counts its scan)."""
        total = sum(len(v) for v in self.sinks.values()) + len(data)
        if total > MAX_OUTPUT:
            raise EmulationError("the call printed more than %d bytes" % MAX_OUTPUT)
        self.sinks[stream] += data

    def _vararg(self, k, size):
        """The k-th integer-class argument of a variadic call (0 is the first register argument), `size`
        (4 or 8) bytes of it: the argument registers first, then the caller's 8-byte stack slots (x86-64 SysV
        and AArch64 AAPCS64 as on Linux; at the trap the x86-64 return address is still on the stack). Only
        the bytes the conversion reads are read from a stack slot (a caller stores an int's 4), and an
        undefined one declines."""
        names = ("rdi", "rsi", "rdx", "rcx", "r8", "r9") if self.x86 else tuple("x%d" % i for i in range(8))
        if k < len(names):
            return self.rr(names[k]) & ((1 << (8 * size)) - 1)
        if k - len(names) >= 32:
            raise EmulationError("printf with more than %d arguments is not modelled" % (len(names) + 32))
        sp = self.rr("rsp" if self.x86 else "sp") + (8 if self.x86 else 0)
        return int.from_bytes(self.read(sp + 8 * (k - len(names)), size), "little")

    def _format(self, fmt, first):
        """printf's output for format bytes `fmt` whose first conversion takes variadic argument `first`.
        Only conversions whose output the C standard fixes are modelled: %% and %c %s %d %i %u %x %X, the
        flags '-' and '0', a decimal width, a precision on %s, and the length modifiers hh h l ll z j t.
        Everything else (floating point, %p, %n, '*', '#', '+', ' ', positional arguments, a precision on an
        integer, a NULL %s, whose text the C libraries print differently) declines."""
        out, i, k, n = bytearray(), 0, first, len(fmt)
        while i < n:
            c = fmt[i]
            i += 1
            if c != 0x25:                                   # '%'
                out.append(c)
                continue
            if i < n and fmt[i] == 0x25:
                out.append(0x25)
                i += 1
                continue
            flags = set()
            while i < n and fmt[i] in b"-0":
                flags.add(fmt[i])
                i += 1
            width = 0
            while i < n and 0x30 <= fmt[i] <= 0x39:
                width = 10 * width + fmt[i] - 0x30
                i += 1
            prec = None
            if i < n and fmt[i] == 0x2E:                    # '.'
                i += 1
                prec = 0
                while i < n and 0x30 <= fmt[i] <= 0x39:
                    prec = 10 * prec + fmt[i] - 0x30
                    i += 1
            bits = 32
            if fmt[i:i + 2] == b"hh":
                bits, i = 8, i + 2
            elif fmt[i:i + 2] == b"ll":
                bits, i = 64, i + 2
            elif i < n and fmt[i] in b"lzjt":
                bits, i = 64, i + 1
            elif i < n and fmt[i] == 0x68:                  # 'h'
                bits, i = 16, i + 1
            if i >= n:
                raise EmulationError("printf format ends inside a conversion")
            conv = chr(fmt[i])
            i += 1
            if width > MAX_OUTPUT or (prec is not None and prec > MAX_OUTPUT):
                raise EmulationError("printf width or precision too large")
            if conv == "s":
                if 0x30 in flags or bits != 32:
                    raise EmulationError("printf %s with a flag or length the model does not take")
                p = self._vararg(k, 8)
                k += 1
                if not p:
                    raise EmulationError("printf %s of NULL (the C libraries differ) is not modelled")
                text = self.cstr(p, MAX_OUTPUT) if prec is None else self._strn(p, prec)
            elif conv == "c":
                if 0x30 in flags or prec is not None or bits != 32:
                    raise EmulationError("printf %c with a flag, precision or length the model does not take")
                text = bytes([self._vararg(k, 4) & 0xFF])
                k += 1
            elif conv in "diuxX":
                if prec is not None:
                    raise EmulationError("printf integer precision is not modelled")
                v = self._vararg(k, 8 if bits == 64 else 4) & ((1 << bits) - 1)
                k += 1
                if conv in "di":
                    if v >> (bits - 1):
                        v -= 1 << bits
                    digits = str(abs(v))
                elif conv == "u":
                    digits = str(v)
                else:
                    digits = "%x" % v if conv == "x" else "%X" % v
                sign = "-" if conv in "di" and v < 0 else ""
                if 0x30 in flags and 0x2D not in flags:
                    digits = digits.rjust(width - len(sign), "0")
                text = (sign + digits).encode("ascii")
            else:
                raise EmulationError("printf conversion %%%s is not modelled" % conv)
            pad = b" " * max(0, width - len(text))
            out += (text + pad) if 0x2D in flags else (pad + text)
        return bytes(out)

    def _sink(self, name):
        """The output imports emulate_call(output="capture") models: their bytes are captured, nothing is
        written anywhere. puts / putchar / printf / __printf_chk go to the stdio stream, write(2) to its file
        descriptor (1 or 2 only). The results are the C standard's (bytes written, the character); puts
        returns "a non-negative value", which the C libraries choose differently: len + 1 in one layout and
        0 in the other (puts_ret), so a program that depends on it declines. A FILE* function (fputs,
        fwrite, fprintf, putc) is not modelled: its stdout / stderr pointer is a data import, undefined."""
        if name == "puts":
            (s,) = self._args(1)
            text = self.cstr(s, MAX_OUTPUT)
            self._emit("stdio", text + b"\n")
            ret = self.L["puts_ret"]
            return (len(text) + 1 if ret is None else ret), "int"
        if name == "putchar":
            (c,) = self._args(1)
            self._emit("stdio", bytes([c & 0xFF]))
            return c & 0xFF, "int"
        if name in ("printf", "__printf_chk"):
            first = 1 if name == "printf" else 2
            fmt_ptr = self._args(first)[first - 1]
            text = self._format(self.cstr(fmt_ptr, MAX_OUTPUT), first)
            self._emit("stdio", text)
            return len(text), "int"
        if name == "write":
            fd, buf, n = self._args(3)
            fd &= M32
            if fd not in (1, 2):
                raise EmulationError("write to file descriptor %d is not modelled" % fd)
            if n > MAX_OUTPUT:
                raise EmulationError("write of %d bytes is not modelled" % n)
            self._emit(fd, self.read(buf, n))
            return n, "ptr"
        raise EmulationError("output function %s is not modelled" % name)

    # --------------------------------------------------------------- JavaVM models (the load phase)
    def _vm(self, name):
        a = self._args(4)
        if a[0] != self.vm_ptr:
            raise EmulationError("JavaVM call with a JavaVM that is not the one passed in")
        if name == "GetEnv":
            ver = a[2] & M32
            if ver not in JNI_VERSIONS_GETENV:
                raise EmulationError("GetEnv with version %#x is not modelled" % ver)
            self.write(a[1], struct.pack("<Q", self.env))
            return 0, "int"
        if name in ("AttachCurrentThread", "AttachCurrentThreadAsDaemon"):
            self.write(a[1], struct.pack("<Q", self.env))     # the thread is attached already: JNI_OK
            return 0, "int"
        raise EmulationError("JavaVM function %s is not modelled" % name)

    def _strn(self, s, n):
        out = bytearray()
        for k in range(n):
            self._charge(64)                   # a byte-at-a-time scan: one access per byte
            ch = self.read(s + k, 1)
            if ch == b"\x00":
                break
            out += ch
        return bytes(out)

    def _cmp_strs(self, a, b, lim):
        x, y = bytearray(), bytearray()
        for k in range(lim):
            self._charge(128)                  # two bytes read per step
            ca, cb = self.read(a + k, 1), self.read(b + k, 1)
            x += ca
            y += cb
            if ca != cb or ca == b"\x00":
                break
        return bytes(x), bytes(y)

    def _cmp(self, x, y):
        """A comparison result whose SIGN is the C standard's and whose magnitude differs between the
        runs (implementation-defined), so code that depends on the magnitude declines."""
        for p, q in zip(x, y):
            if p != q:
                return (-1 if p < q else 1) * self.L["cmp_scale"]
        if len(x) != len(y):
            raise EmulationError("comparison of unequal-length reads")
        return 0

    # --------------------------------------------------------------- JNI models
    def _jni(self, name):
        a = self._args(6)
        if a[0] != self.env:
            raise EmulationError("JNI call with a JNIEnv that is not the one passed in")
        if name == "ExceptionCheck":
            return 0, "bool"
        if name == "GetStringUTFChars":
            o = self.obj(a[1], JStr)
            raw = _mutf8_encode(o.text) + b"\x00"
            self._charge(len(raw))
            p = self.malloc(len(raw))
            self.write(p, raw)
            self.utf_out[p] = a[1] & M64
            if a[2]:
                self.write(a[2], b"\x01")
            return p, "ptr"
        if name == "ReleaseStringUTFChars":
            if self.utf_out.get(a[2]) != (a[1] & M64):
                raise EmulationError("ReleaseStringUTFChars of a buffer that string did not hand out")
            del self.utf_out[a[2]]
            self.free(a[2])
            return 0, "void"
        if name == "GetStringUTFLength":
            return len(_mutf8_encode(self.obj(a[1], JStr).text)), "int"
        if name == "GetStringLength":
            return _utf16_len(self.obj(a[1], JStr).text), "int"
        if name == "NewStringUTF":
            if a[1] == 0:
                raise EmulationError("NewStringUTF(NULL) not modelled")
            return self.new_handle(JStr(_mutf8_decode(self.cstr(a[1])))), "ptr"
        if name == "GetArrayLength":
            return len(self.obj(a[1], JArr).values), "int"
        if name in ("GetByteArrayElements", "GetIntArrayElements"):
            kind = "B" if name.startswith("GetByte") else "I"
            o = self.obj(a[1], JArr)
            if o.kind != kind:
                raise EmulationError("%s on an array of another element type" % name)
            if self._outstanding(a[1]):
                # a second elements buffer of one array: a VM that pins hands out the SAME memory (a write through
                # one is seen through the other), a VM that copies hands out two copies; the model cannot tell
                raise EmulationError("%s of an array whose elements buffer is still held (pinned vs. copied "
                                     "arrays differ)" % name)
            raw = self._arr_bytes(o)
            self._charge(len(raw))
            p = self.malloc(max(len(raw), 1))
            if raw:
                self.write(p, raw)
            if len(raw) == 0:                         # a zero-length buffer: nothing is writable
                self.rheap.writable[p - self.rheap.lo] = 0
            self.elems[p] = [a[1] & M64, kind, len(raw), raw]
            if a[2]:
                self.write(a[2], bytes([self.L["iscopy"]]))
            return p, "ptr"
        if name in ("ReleaseByteArrayElements", "ReleaseIntArrayElements"):
            kind = "B" if name.startswith("ReleaseByte") else "I"
            ent = self.elems.get(a[2])
            mode = _sx32(a[3])
            if ent is None or ent[0] != (a[1] & M64) or ent[1] != kind:
                raise EmulationError("%s of a buffer that array did not hand out" % name)
            if mode not in (0, JNI_COMMIT, JNI_ABORT):
                raise EmulationError("%s mode %d not modelled" % (name, mode))
            n = ent[2]
            self._charge(n)
            now = self.read(a[2], n) if n else b""
            o = self.obj(a[1], JArr)
            if mode == JNI_ABORT:
                if now != ent[3]:
                    raise EmulationError("JNI_ABORT of a modified buffer (copy vs. pinned semantics differ)")
            else:
                self._arr_store(o, 0, now)
                ent[3] = now
            if mode in (0, JNI_ABORT):
                del self.elems[a[2]]
                self.free(a[2])
            return 0, "void"
        if name in ("GetByteArrayRegion", "SetByteArrayRegion"):
            o = self.obj(a[1], JArr)
            if o.kind != "B":
                raise EmulationError("%s on an array that is not byte[]" % name)
            start, ln = _sx32(a[2]), _sx32(a[3])
            if start < 0 or ln < 0 or start + ln > len(o.values):
                raise EmulationError("%s out of bounds (ArrayIndexOutOfBoundsException not modelled)" % name)
            held = self._outstanding(a[1])
            if held and (name == "SetByteArrayRegion" or
                         any(self.read_shadow(p, ent[2])[0] != ent[3] for p, ent in held if ent[2])):
                # with an elements buffer of this array held: a VM that pins sees the buffer's writes through the
                # region read and the region write through the buffer, a VM that copies sees neither
                raise EmulationError("%s of an array whose elements buffer is held%s (pinned vs. copied arrays "
                                     "differ)" % (name, "" if name == "SetByteArrayRegion" else " and modified"))
            self._charge(ln)
            if name == "GetByteArrayRegion":
                if ln:
                    self.write(a[4], bytes(v & 0xFF for v in o.values[start:start + ln]))
            else:
                if ln:
                    self._arr_store(o, start, self.read(a[4], ln))
            return 0, "void"
        if name == "NewByteArray":
            n = _sx32(a[1])
            if n < 0 or n > MAX_JARRAY:
                raise EmulationError("NewByteArray(%d) not modelled" % n)
            self._charge(n)
            return self.new_handle(JArr("B", [0] * n)), "ptr"
        if name == "GetVersion":
            return 0x00010006, "int"
        if name == "ExceptionOccurred":
            return 0, "ptr"                            # never a pending exception: every throw declines
        if name == "ExceptionClear":
            return 0, "void"
        if name == "DeleteLocalRef":
            h = a[1] & M64
            if h:
                if self.handles.get(h) is None:
                    raise EmulationError("JNI call with a reference that is not a live handle")
                if self.ref_kind[h] != "local":
                    # CheckJNI aborts on it, ART without CheckJNI logs and ignores it: the build decides
                    raise EmulationError("DeleteLocalRef of a reference that is not a local reference")
                self.drop_handle(h)                    # any later use of it declines
            return 0, "void"
        if name in JNI_LIFECYCLE:
            return self._jni_lifecycle(name, a)
        if name == "FindClass":
            raw = self.cstr(a[1], 1024)
            try:
                cname = raw.decode("ascii")
            except UnicodeDecodeError:
                raise EmulationError("FindClass of a non-ASCII name is not modelled")
            if cname.startswith("["):
                raise EmulationError("FindClass of an array class is not modelled")
            cname = cname.replace(".", "/")            # ART's NormalizeJniClassDescriptor
            if cname not in self.classes:
                raise EmulationError("FindClass(%r): not a class the delivery's dex defines" % cname[:120])
            return self.new_handle(JClass(cname)), "ptr"
        if name == "RegisterNatives":
            if self.phase != "load":
                raise EmulationError("RegisterNatives during a call would change later calls (not modelled)")
            cls = self.obj(a[1], JClass)
            meth, n = a[2], _sx32(a[3])
            if not 0 < n <= MAX_REGISTER:
                raise EmulationError("RegisterNatives with %d methods is not modelled" % n)
            for k in range(n):
                np_, sp_, fn = struct.unpack("<QQQ", self.read(meth + 24 * k, 24))
                try:
                    mname = self.cstr(np_, 1024).decode("utf-8")
                    sig = self.cstr(sp_, 4096).decode("utf-8")
                except UnicodeDecodeError:
                    raise EmulationError("RegisterNatives with a name that is not UTF-8")
                key = (cls.name, mname, sig)
                if key not in self.natives:
                    raise EmulationError("RegisterNatives of %s.%s%s: not a native method the dex declares "
                                         "(ART fails the registration)" % (cls.name[:80], mname[:40], sig[:80]))
                va = fn - self.base
                if self.find(fn) is not self.rimg or not self.img._in_exec(va):
                    raise EmulationError("RegisterNatives of a function pointer outside the image's code")
                if self.registered.get(key, va) != va:
                    raise EmulationError("one method registered to two different functions")
                self.registered[key] = va
            return 0, "int"
        raise EmulationError("JNI function %s is not modelled" % name)

    def _jni_lifecycle(self, name, a):
        """The JNI reference lifecycle (B-241). References are handles to Python-side objects; what a device
        could answer differently (a capacity only some ART versions grant, a weak reference the collector may
        have cleared, a call CheckJNI aborts on) declines."""
        h = a[1] & M64
        if name in ("NewGlobalRef", "NewLocalRef", "NewWeakGlobalRef"):
            if h == 0:
                return 0, "ptr"                        # a reference to null is null
            kind = {"NewGlobalRef": "global", "NewLocalRef": "local", "NewWeakGlobalRef": "weak"}[name]
            return self.new_handle(self.strong(h, name), kind), "ptr"
        if name in ("DeleteGlobalRef", "DeleteWeakGlobalRef"):
            kind = "global" if name == "DeleteGlobalRef" else "weak"
            if h:
                if self.handles.get(h) is None or self.ref_kind[h] != kind:
                    raise EmulationError("%s of a reference that is not a live %s reference" % (
                        name, "global" if kind == "global" else "weak global"))
                if self.phase == "call" and h in self.load_refs:
                    raise EmulationError("%s of a reference the load phase created would change later calls "
                                         "(state escapes the call)" % name)
                self.drop_handle(h)
            return 0, "void"
        if name in ("PushLocalFrame", "EnsureLocalCapacity"):
            cap = _sx32(a[1])
            if not 0 <= cap <= LOCAL_FRAME_CAPACITY:
                raise EmulationError("%s(%d): a capacity ART versions answer differently" % (name, cap))
            if name == "PushLocalFrame":
                if len(self.frames) >= MAX_LOCAL_FRAMES:
                    raise EmulationError("PushLocalFrame nested deeper than the model follows")
                self.frames.append(set())
            return 0, "int"
        if name == "PopLocalFrame":
            if not self.frames:
                raise EmulationError("PopLocalFrame without a PushLocalFrame")
            keep = self.strong(h, name) if h else None
            for dead in list(self.frames.pop()):
                if dead in self.handles:
                    self.drop_handle(dead)
            return (self.new_handle(keep), "ptr") if h else (0, "ptr")
        if name == "GetObjectRefType":
            if h == 0:
                return 0, "int"                        # JNIInvalidRefType
            if self.handles.get(h) is None:
                raise EmulationError("GetObjectRefType of a reference that is not a live handle")
            return JNI_REF_TYPES[self.ref_kind[h]], "int"
        if name == "IsSameObject":
            other = a[2] & M64
            for ref in (h, other):
                if ref and (self.handles.get(ref) is None or self.ref_kind[ref] == "weak"):
                    # a cleared weak reference is the same object as null: the collector decides
                    raise EmulationError("IsSameObject of a reference that is not a live strong reference")
            same = (h == 0 and other == 0) or (h and other and self.handles[h] is self.handles[other])
            return (1 if same else 0), "bool"
        if name == "GetJavaVM":
            self.write(a[1], struct.pack("<Q", self.vm_ptr))
            return 0, "int"
        if name in ("MonitorEnter", "MonitorExit"):
            if h == 0:
                raise EmulationError("%s(NULL) throws (not modelled)" % name)
            key = id(self.obj(h))
            held = self.monitors.get(key, 0)
            if name == "MonitorEnter":
                self.monitors[key] = held + 1
            elif not held:
                raise EmulationError("MonitorExit of a monitor this thread does not hold (it throws)")
            else:
                self.monitors[key] = held - 1
            return 0, "int"
        raise EmulationError("JNI function %s is not modelled" % name)

    def _outstanding(self, h):
        """[(pointer, entry)] of the Get<Prim>ArrayElements buffers of array reference `h` not yet released."""
        h &= M64
        return [(p, ent) for p, ent in self.elems.items() if ent[0] == h]

    @staticmethod
    def _arr_bytes(o):
        if o.kind == "B":
            return bytes(v & 0xFF for v in o.values)
        return b"".join(struct.pack("<I", v & M32) for v in o.values)

    @staticmethod
    def _arr_store(o, start, raw):
        if o.kind == "B":
            for k, ch in enumerate(raw):
                o.values[start + k] = ch - 256 if ch & 0x80 else ch
        else:
            for k in range(len(raw) // 4):
                o.values[start + k] = _sx32(struct.unpack_from("<I", raw, 4 * k)[0])

    def finish_jni(self):
        """Decline when a native left an array buffer modified and never committed it (its effect would
        depend on whether the VM pinned or copied the array)."""
        for p, ent in self.elems.items():
            n = ent[2]
            if n and self.read_shadow(p, n)[0] != ent[3]:
                raise EmulationError("a modified Get<Prim>ArrayElements buffer was never released")
        if any(self.monitors.values()):
            raise EmulationError("the native returned holding a JNI monitor")


# ==================================================================================================== JNI entry
class JniResult:
    """The agreed outcome of a JNI call: `value` (int / str / list / None), `kind` ('int', 'float', 'double',
    'str', 'cstr', 'arr', 'null', 'void'), and `commits` {arg index: new element list} for Java arrays the
    native changed. A 'float' / 'double' value is the IEEE bit pattern (an int): fp_value() converts it."""
    __slots__ = ("value", "kind", "commits", "arr_arg")

    def __init__(self, value, kind, commits, arr_arg=None):
        self.value, self.kind, self.commits, self.arr_arg = value, kind, commits, arr_arg


_INT_KINDS = {"Z": 8, "B": 8, "S": 16, "C": 16, "I": 32, "J": 64}
_FP_FORMAT = {"F": ("<f", "<I", 32), "D": ("<d", "<Q", 64)}


def fp_bits(kind, value):
    """The IEEE bit pattern of a jfloat ("F") / jdouble ("D") argument: an int is taken as the pattern itself
    (how a Dalvik register holds it), a Python float is converted and, for "F", must be a float32 value."""
    fmt, ifmt, width = _FP_FORMAT[kind]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SetupError("non-numeric value for a %s argument" % kind)
    if isinstance(value, int):
        if not 0 <= value < (1 << width):
            raise SetupError("a %s bit pattern outside %d bits" % (kind, width))
        return value
    try:
        raw = struct.pack(fmt, value)
    except OverflowError:
        raise SetupError("a value outside the float32 range for an F argument")
    if value == value and struct.unpack(fmt, raw)[0] != value:
        raise SetupError("a value that is not a float32 for an F argument")
    return struct.unpack(ifmt, raw)[0]


def fp_value(kind, bits):
    """The Python float of a 'float' ("F") / 'double' ("D") bit pattern."""
    fmt, ifmt, _width = _FP_FORMAT[kind]
    return struct.unpack(fmt, struct.pack(ifmt, bits))[0]


def _fp_is_nan(kind, bits):
    width = _FP_FORMAT[kind][2]
    exp_bits, frac_bits = (8, 23) if width == 32 else (11, 52)
    return (bits >> frac_bits) & ((1 << exp_bits) - 1) == (1 << exp_bits) - 1 and bits & ((1 << frac_bits) - 1)


def _narrow(kind, v):
    if kind == "J":
        return v & M64
    if kind == "I":
        return _sx32(v)
    if kind == "S":
        v &= 0xFFFF
        return v - 0x10000 if v & 0x8000 else v
    if kind == "C":
        return v & 0xFFFF
    if kind == "B":
        v &= 0xFF
        return v - 0x100 if v & 0x80 else v
    if kind == "Z":
        v &= 0xFF
        if v not in (0, 1):
            raise EmulationError("jboolean return outside 0/1")
        return v
    raise EmulationError("return kind %r not modelled" % kind)


def _one_jni(img, entry, jargs, ret, static, layout, max_blocks, max_mem, usage, classes=(), natives=()):
    run = _Run(img, layout, max_blocks, max_mem, classes, natives)
    try:
        return _one_jni_run(run, entry, jargs, ret, static)
    finally:
        if usage is not None:
            usage["blocks"] = usage.get("blocks", 0) + run.blocks
            usage["mem"] = usage.get("mem", 0) + run.mem


def _one_jni_run(run, entry, jargs, ret, static):
    run.load(jni=True)             # constructors and JNI_OnLoad first, as the loader and ART run them
    args = [(run.env, 64), (run.new_handle(JOpaque("class" if static else "this")), 64)]
    arrays = {}
    for k, (kind, val) in enumerate(jargs):
        if kind in _INT_KINDS:
            if not isinstance(val, int):
                raise SetupError("non-integer value for a %s argument" % kind)
            v = _narrow(kind, val) if kind != "Z" else (1 if val else 0)
            args.append(((v & M64), 64 if kind == "J" else 32))
        elif kind in ("F", "D"):
            args.append((fp_bits(kind, val), kind))
        elif val is None:
            args.append((0, 64))
        elif kind == "str":
            if not isinstance(val, str):
                raise SetupError("non-string value for a String argument")
            args.append((run.new_handle(JStr(val)), 64))
        elif kind.startswith("arr:"):
            if not isinstance(val, list):
                raise SetupError("non-list value for an array argument")
            ek = kind[4:]
            if ek == "B" and not all(isinstance(x, int) and -128 <= x <= 127 for x in val):
                raise SetupError("byte[] argument holds a value outside a signed byte")
            if ek == "I" and not all(isinstance(x, int) and -(1 << 31) <= x < (1 << 31) for x in val):
                raise SetupError("int[] argument holds a value outside a signed int")
            o = JArr(ek, list(val), k)
            arrays[k] = o
            args.append((run.new_handle(o), 64))
        elif kind == "obj":
            args.append((run.new_handle(JOpaque("obj")), 64))
        else:
            raise SetupError("argument kind %r not modelled" % kind)
    raw = run.call(entry, args, ret_fp=ret if ret in ("F", "D") else None)
    run.finish_jni()
    commits = {k: tuple(o.values) for k, o in arrays.items()}
    if ret == "V":
        return ("void", None, None), commits
    if ret in _INT_KINDS:
        return ("int", _narrow(ret, raw), None), commits
    if ret in ("F", "D"):
        if _fp_is_nan(ret, raw):
            # which NaN an operation gives (its sign, its payload) is the processor's choice, not the bytes'
            raise EmulationError("the native returned a NaN (its sign and payload are the processor's)")
        return ("float" if ret == "F" else "double", raw, None), commits
    if raw == 0:
        return ("null", None, None), commits
    if run.ref_kind.get(raw) == "weak":
        raise EmulationError("returned a weak global reference (the collector decides what it holds)")
    o = run.handles.get(raw)
    if isinstance(o, JStr) and ret in ("str", "obj", "?"):
        return ("str", o.text, None), commits
    if isinstance(o, JArr) and (ret.startswith("arr:") or ret in ("obj", "?")):
        if ret.startswith("arr:") and ret[4:] not in ("?", o.kind):
            raise EmulationError("returned array of another element type")
        return ("arr", tuple(o.values), o.arg), commits
    if o is not None:
        raise EmulationError("returned a reference this model does not convert")
    if ret == "str":
        # The fixture generator's shortcut: a `jstring` that is really a C pointer to a NUL-terminated text.
        text = _mutf8_decode(run.cstr(raw, 4096))
        return ("cstr", text, None), commits
    raise EmulationError("returned a value that is not a live reference")


def _run_caps(k, max_blocks, max_mem, total_blocks, total_mem, spent):
    """(blocks, memory accesses) the run in layout `k` may use: its per-run cap, and with a total for both runs
    (KB-2 fix round 2, the review of 4250749: each run was handed the whole remainder, so two runs could spend twice it)
    only what the runs before it left. BudgetError when nothing is left."""
    mb = max_blocks if total_blocks is None else min(max_blocks, total_blocks - spent[0])
    mm = max_mem if total_mem is None else min(max_mem, total_mem - spent[1])
    if mb <= 0 or mm <= 0:
        raise BudgetError("the work budget is spent before the run in layout %d" % k)
    return mb, mm


def call_jni(img, symbol, jargs, ret, static=True, max_blocks=DEFAULT_MAX_BLOCKS, max_mem=DEFAULT_MAX_MEM,
             usage=None, classes=(), natives=(), entry=None, total_blocks=None, total_mem=None):
    """Call the JNI function `symbol` of `img` as ART would: (JNIEnv*, jclass|jobject, args...).

    The function is the exported `symbol` (ART's dlsym binding), or, with `entry`, the image vaddr a
    RegisterNatives bound (load_info). Before the call each run does the load phase: the image's
    constructors, then its JNI_OnLoad (see _Run.load). `classes` (internal names) are the classes FindClass
    may answer and `natives` the (class, name, signature) triples RegisterNatives may bind: the delivery's own
    dex. `jargs` is [(kind, value)] with kind Z/B/S/C/I/J (int), F/D (a jfloat / jdouble: its IEEE bit pattern
    as an int, or a Python float; at most eight), str (a Python str or None), arr:B / arr:I / arr:? (a Python
    list or None; '?' = element type unknown: only GetArrayLength works on it), obj (an opaque reference).
    `ret` is Z/B/S/C/I/J/F/D/V, str, arr:B/arr:I/arr:?, obj or '?'; an F / D result is its bit pattern. Two runs in different
    layouts must agree on the result and on every array's final content. `usage`, a dict, receives the
    blocks and memory accesses both runs spent (also on a decline). `total_blocks` / `total_mem`, when given, bound
    BOTH runs together: each run gets at most its per-run cap and what the run before it left (a run is charged at
    most its cap). Raises EmulationError."""
    if not UNICORN_AVAILABLE:
        raise SetupError("unicorn engine not available")
    if isinstance(img, (bytes, bytearray)):
        img = load(img)
    if img.problem:
        raise SetupError(img.problem)
    if entry is None:
        entry = img.exports().get(symbol)
        if entry is None:
            raise SetupError("no exported symbol %s" % symbol)
    elif not img._in_exec(entry):
        raise SetupError("entry %#x is not inside an executable segment" % entry)
    arr_ids = [id(v) for (k, v) in jargs if isinstance(k, str) and k.startswith("arr:") and v is not None]
    if len(arr_ids) != len(set(arr_ids)):
        raise SetupError("one Java array passed as two arguments (aliasing is not modelled)")
    out, spent = [], [0, 0]
    for k in (0, 1):
        mb, mm = _run_caps(k, max_blocks, max_mem, total_blocks, total_mem, spent)
        u = {}
        try:
            out.append(_one_jni(img, entry, jargs, ret, static, k, mb, mm, u, classes, natives))
        finally:
            ub, um = min(u.get("blocks", 0), mb), min(u.get("mem", 0), mm)
            spent[0] += ub
            spent[1] += um
            if usage is not None:
                usage["blocks"] = usage.get("blocks", 0) + ub
                usage["mem"] = usage.get("mem", 0) + um
    if out[0] != out[1]:
        raise EmulationError("the two runs disagree (the result depends on an address, a handle, poison or "
                             "an implementation-defined detail)")
    (kind, value, arr_arg), commits = out[0]
    changed = {k: list(v) for k, v in commits.items() if list(v) != list(jargs[k][1])}
    if kind == "arr":
        value = list(value)
    return JniResult(value, kind, changed, arr_arg)


def load_info(img, classes=(), natives=(), max_blocks=DEFAULT_MAX_BLOCKS, max_mem=DEFAULT_MAX_MEM, usage=None,
              total_blocks=None, total_mem=None):
    """What loading `img` into an app does before any native call, agreed by two runs in different layouts:
    {"load_code": bool, "version": JNI_OnLoad's version or None, "registered": {(class, name, signature):
    vaddr}}. An image with no constructor and no JNI_OnLoad answers at once (load_code False, nothing
    registered). Raises EmulationError when the load phase cannot be modelled (an unmodelled import, JNI or
    JavaVM call, a FindClass of a class not in `classes`, a RegisterNatives of a method not in `natives`, a
    version ART refuses, ...): then nothing about the image's bindings is known. Cached on the image. `usage`, a
    dict, receives the blocks and memory accesses both runs spent (also on a decline, and also when the answer
    comes from the cache: the work it cost when it was computed), so a caller's budget is charged the same way
    whether the answer was cached or not. `total_blocks` / `total_mem` bound both runs together, as in call_jni."""
    if not UNICORN_AVAILABLE:
        raise SetupError("unicorn engine not available")
    if isinstance(img, (bytes, bytearray)):
        img = load(img)
    if img.problem:
        raise SetupError(img.problem)
    if not img.has_load_code(jni=True):
        return {"load_code": False, "version": None, "registered": {}}
    key = (frozenset(classes or ()), frozenset(natives or ()), max_blocks, max_mem, total_blocks, total_mem)
    cache = img.__dict__.setdefault("_load_cache", {})
    if key in cache:
        got, spent = cache[key]
        if usage is not None:
            usage["blocks"] = usage.get("blocks", 0) + spent[0]
            usage["mem"] = usage.get("mem", 0) + spent[1]
        if isinstance(got, EmulationError):
            raise type(got)(str(got))
        return {"load_code": True, "version": got[0], "registered": dict(got[1])}
    outs = []
    spent = [0, 0]
    try:
        for layout in (0, 1):
            mb, mm = _run_caps(layout, max_blocks, max_mem, total_blocks, total_mem, spent)
            run = _Run(img, layout, mb, mm, classes, natives)
            try:
                version = run.load(jni=True)
            finally:
                spent[0] += min(run.blocks, mb)
                spent[1] += min(run.mem, mm)
            outs.append((version, tuple(sorted(run.registered.items()))))
        if outs[0] != outs[1]:
            raise EmulationError("the two load runs disagree (the bindings depend on an address or poison)")
    except EmulationError as e:
        if len(cache) > 64:
            cache.clear()
        cache[key] = (e, tuple(spent))
        if usage is not None:
            usage["blocks"] = usage.get("blocks", 0) + spent[0]
            usage["mem"] = usage.get("mem", 0) + spent[1]
        raise
    if len(cache) > 64:
        cache.clear()
    cache[key] = (outs[0], tuple(spent))
    if usage is not None:
        usage["blocks"] = usage.get("blocks", 0) + spent[0]
        usage["mem"] = usage.get("mem", 0) + spent[1]
    return {"load_code": True, "version": outs[0][0], "registered": dict(outs[0][1])}


# ==================================================================================================== plain C entry
def emulate_symbol(elf_bytes, symbol_or_vaddr, args, arch=None, ret="int", max_blocks=DEFAULT_MAX_BLOCKS,
                   max_mem=DEFAULT_MAX_MEM, init="auto"):
    """Run one function of a whole ELF image (x86-64 SysV or AArch64 AAPCS64) and return its result. A 64-bit
    Mach-O file is taken too (B-241, macho_image.py): its symbols are named without the linker's leading
    underscore, its addresses are relative to the Mach header, and `arch` picks the slice of a universal file.

    `symbol_or_vaddr` is a symbol name (dynamic exports first, then the static .symtab) or an image vaddr.
    `args` are ints (64-bit), or bytes/bytearray: copied into the bounded heap (defined, writable for their
    length) and passed as a pointer; a bytearray argument is updated in place with the final content when
    both runs agree on it. `arch`, when given, must match the image ("x86-64" / "arm64"). `ret="int"`
    returns the 64-bit return register; `ret="cstr"` reads the returned pointer as a NUL-terminated strict
    UTF-8 string (inside the image or the heap). `init="auto"` (the default) first runs the image's
    constructors as the loader would (DT_PREINIT_ARRAY of an executable, DT_INIT, DT_INIT_ARRAY; a static
    executable whose section headers name a constructor table declines), so a function that reads data a
    constructor prepared reads the prepared data; `init="skip"` runs the function on the pristine image (the
    caller asserts no constructor matters). Never-wrong: two runs in different layouts must agree;
    anything undefined, unmodelled or over budget raises EmulationError. For a release-morning
    fields_dNN.py: never answer a plain value from it unless its key is judged (it is a reader, not a label)."""
    if not UNICORN_AVAILABLE:
        raise EmulationError("unicorn engine not available")
    if init not in ("auto", "skip"):
        raise EmulationError("init must be 'auto' or 'skip'")
    img = load(elf_bytes, arch, macho=True)
    if arch is not None and arch != img.arch:
        raise EmulationError("image is %s, not %s" % (img.arch, arch))
    if img.problem:
        raise EmulationError(img.problem)
    if isinstance(symbol_or_vaddr, str):
        entry = img.symbol(symbol_or_vaddr)
        if entry is None:
            raise EmulationError("no function symbol %s" % symbol_or_vaddr)
    else:
        entry = int(symbol_or_vaddr)
        if not img._in_exec(entry):
            raise EmulationError("vaddr %#x is not inside an executable segment" % entry)
    if ret not in ("int", "cstr"):
        raise EmulationError("ret must be 'int' or 'cstr'")
    outs = []
    for layout in (0, 1):
        run = _Run(img, layout, max_blocks, max_mem)
        if init == "auto":
            run.load(jni=False)
        cargs, bufs = [], {}
        for k, a in enumerate(args):
            if isinstance(a, bool) or not isinstance(a, (int, bytes, bytearray)):
                raise EmulationError("argument %d must be an int, bytes or bytearray" % k)
            if isinstance(a, int):
                cargs.append((a & M64, 64))
            else:
                p = run.malloc(max(len(a), 1))
                if len(a):
                    run.write(p, bytes(a))
                else:
                    run.rheap.writable[p - run.rheap.lo] = 0
                bufs[k] = (p, len(a))
                cargs.append((p, 64))
        raw = run.call(entry, cargs)
        if ret == "cstr":
            if raw == 0:
                raise EmulationError("returned NULL")
            r = run.find(raw)
            if r is None or r.name not in ("image", "heap"):
                raise EmulationError("returned pointer is not inside the image or the heap")
            value = _mutf8_decode(run.cstr(raw, 4096))
        else:
            value = raw
        finals = {}
        for k, (p, n) in bufs.items():
            if isinstance(args[k], bytearray) and n:
                data, dd = run.read_shadow(p, n)
                if dd != _ones(n):
                    raise EmulationError("buffer argument %d ends partly undefined" % k)
                finals[k] = data
        outs.append((value, finals))
    if outs[0] != outs[1]:
        raise EmulationError("the two runs disagree (the result depends on an address, poison or an "
                             "implementation-defined detail)")
    value, finals = outs[0]
    for k, data in finals.items():
        args[k][:] = data
    return value


# ---------------------------------------------------------------------------------- B-166: bound calls
MAX_OUTBUF = 1 << 16           # the largest output buffer emulate_call hands a function
MAX_CHANGES = 16               # runs of changed image bytes emulate_call reports (state="report")
MAX_CHANGE_BYTES = 1 << 16     # bytes in one such run
CHANGE_GAP = 16                # changed bytes at most this far apart are one run
MAX_OUTPUT = 1 << 16           # bytes a call may print (output="capture") before it declines
# The output imports emulate_call(output="capture") models as captured sinks (_Run._sink).
SINK_FUNCS = ("puts", "putchar", "printf", "__printf_chk", "write")


class ImagePtr:
    """An emulate_call argument: the run address of image vaddr `vaddr`. The load bias differs between the
    two layouts, so the pointer the program itself would pass is rebuilt in each run."""
    __slots__ = ("vaddr",)

    def __init__(self, vaddr):
        self.vaddr = int(vaddr)


class OutBuf:
    """An emulate_call argument: a pointer to `size` writable, UNDEFINED heap bytes (an output buffer). A
    read of a byte the function did not write first declines, so a buffer the caller filled before the call
    (an in/out buffer) is never decoded from zeros. `init` ((offset, bytes), ...) defines the bytes a caller
    is known to have stored there before the call (B-166 fix round 1: a stack string, an in/out buffer);
    every other byte stays undefined. After the call `data` holds the bytes both runs agreed on (an
    undefined byte reads 0) and `defined` one flag byte per byte."""
    __slots__ = ("size", "init", "data", "defined")

    def __init__(self, size, init=()):
        self.size = int(size)
        self.init = tuple((int(o), bytes(b)) for o, b in init)
        self.data = None
        self.defined = None

    def written(self):
        """The defined prefix of the buffer: what the function wrote from its start, contiguously."""
        if self.data is None:
            return b""
        n = self.defined.find(b"\x00")
        return self.data if n < 0 else self.data[:n]


class CallResult:
    """What emulate_call established. `value`: the 64-bit return register when both runs agree on all of it,
    else None. `value32`: its low 32 bits when both runs agree on them (an `int` return leaves the upper half
    unspecified), else None. `cstr`: the NUL-terminated bytes at the returned pointer when it points into the
    image or the heap in both runs and both read the same defined string, else None. `changes`: with
    state="report", [(vaddr, bytes)] of the image's writable memory the call changed (always [] with
    state="check", which declines such a call)."""
    __slots__ = ("value", "value32", "cstr", "changes", "stdout", "stderr")

    def __init__(self, value, value32, cstr, changes, stdout=b"", stderr=b""):
        self.value, self.value32, self.cstr, self.changes = value, value32, cstr, changes
        self.stdout, self.stderr = stdout, stderr      # output="capture": what the call printed (B-166 round 1)


def _defined_only(data, defined):
    """`data` with every byte whose definedness flag is 0 read as 0: what an undefined byte happens to hold
    (a stale stack or heap byte) is not part of a result and must not make the two runs disagree."""
    return bytes(b if d else 0 for b, d in zip(data, defined))


def _state_changes(run):
    """[(image vaddr, bytes)] of the runs of writable image memory a call changed, for emulate_call's
    state="report". Changed bytes at most CHANGE_GAP apart are one run (a decoded byte may equal the byte it
    replaced). A changed byte that ended undefined, a change to thread-local storage, more than MAX_CHANGES
    runs or a run longer than MAX_CHANGE_BYTES declines."""
    r, out = run.rimg, []
    for (s, e), before, dbefore in zip(run.rw_ranges, run.rw_before, run.rw_def_before):
        now = bytes(run.uc.mem_read(s, e - s))
        dnow = bytes(r.defined[s - r.lo:e - r.lo])
        if now == before and dnow == dbefore:
            continue
        diff = [i for i in range(e - s) if now[i] != before[i] or dnow[i] != dbefore[i]]
        lo = hi = diff[0]
        runs = []
        for i in diff[1:]:
            if i - hi > CHANGE_GAP:
                runs.append((lo, hi + 1))
                lo = i
            hi = i
        runs.append((lo, hi + 1))
        for lo, hi in runs:
            if hi - lo > MAX_CHANGE_BYTES:
                raise EmulationError("the call changed more than %d bytes of the image in one run" % MAX_CHANGE_BYTES)
            if dnow[lo:hi] != _ones(hi - lo):
                raise EmulationError("the call left image memory it changed undefined")
            out.append((s - run.base + lo, now[lo:hi]))
    if len(out) > MAX_CHANGES:
        raise EmulationError("the call changed more than %d runs of the image's writable memory" % MAX_CHANGES)
    rt, tb = run.rtls, run.tls_before
    if bytes(run.uc.mem_read(rt.lo, rt.hi - rt.lo)) != tb[0] or bytes(rt.defined) != tb[1]:
        raise EmulationError("the call changed thread-local storage (state escapes the call)")
    return out


def emulate_call(elf_bytes, symbol_or_vaddr, args, arch=None, max_blocks=DEFAULT_MAX_BLOCKS,
                 max_mem=DEFAULT_MAX_MEM, init="auto", state="check", output="decline"):
    """Run one function of a whole ELF image with BOUND arguments and report everything it produced.

    Like emulate_symbol (same loader, definedness, budgets and two-layout agreement), with two more argument
    kinds, for a call rebuilt from a call site: `ImagePtr(vaddr)` passes the image's own pointer (relocated
    and constructor-prepared data is read where the program reads it) and `OutBuf(size)` an undefined
    writable buffer whose final content is returned in the object. An int is a 64-bit integer, bytes /
    bytearray a defined heap copy (a bytearray is updated in place). `state="check"` (the default) declines a
    call that changes the image's writable memory, as emulate_symbol does; `state="report"` allows it and
    returns the changed runs in `CallResult.changes`: the result is then that of the FIRST call after the load
    phase (a decoder that fills a global buffer), which the caller must say. `output="decline"` (the default)
    declines a call into an output import, as every other entry does; `output="capture"` models the
    SINK_FUNCS (puts, putchar, printf, __printf_chk, write to fd 1 / 2) and returns what the call printed in
    `CallResult.stdout` / `stderr` (output during the load phase still declines, and so does a call that
    prints to fd 1 both through stdio and through write(2): their order depends on stdio's buffering).
    An OutBuf's `init` bytes are defined before the call. Returns a CallResult.
    Never-wrong: every OutBuf (bytes and definedness), every bytearray and every reported change must be
    identical in both runs, and when the call produced none of those at least one of value / value32 / cstr
    must agree; otherwise EmulationError. A return register the runs disagree on is None, never a guess."""
    if not UNICORN_AVAILABLE:
        raise EmulationError("unicorn engine not available")
    if init not in ("auto", "skip"):
        raise EmulationError("init must be 'auto' or 'skip'")
    if state not in ("check", "report"):
        raise EmulationError("state must be 'check' or 'report'")
    if output not in ("decline", "capture"):
        raise EmulationError("output must be 'decline' or 'capture'")
    img = load(elf_bytes)
    if arch is not None and arch != img.arch:
        raise EmulationError("image is %s, not %s" % (img.arch, arch))
    if img.problem:
        raise EmulationError(img.problem)
    if isinstance(symbol_or_vaddr, str):
        entry = img.symbol(symbol_or_vaddr)
        if entry is None:
            raise EmulationError("no function symbol %s" % symbol_or_vaddr)
    else:
        entry = int(symbol_or_vaddr)
        if not img._in_exec(entry):
            raise EmulationError("vaddr %#x is not inside an executable segment" % entry)
    for k, a in enumerate(args):
        if isinstance(a, ImagePtr):
            if img.seg_of(a.vaddr) is None:
                raise EmulationError("argument %d: vaddr %#x is not inside a segment of the image" % (k, a.vaddr))
        elif isinstance(a, OutBuf):
            if not 1 <= a.size <= MAX_OUTBUF:
                raise EmulationError("argument %d: an output buffer of %d bytes is not modelled" % (k, a.size))
            if any(o < 0 or o + len(b) > a.size for o, b in a.init):
                raise EmulationError("argument %d: initial bytes outside the output buffer" % k)
        elif isinstance(a, bool) or not isinstance(a, (int, bytes, bytearray)):
            raise EmulationError("argument %d must be an int, bytes, bytearray, ImagePtr or OutBuf" % k)
    outs = []
    for layout in (0, 1):
        run = _Run(img, layout, max_blocks, max_mem)
        if init == "auto":
            run.load(jni=False)
        if output == "capture":
            run.sinks = {"stdio": bytearray(), 1: bytearray(), 2: bytearray()}
        cargs, bufs, made = [], [], {}
        for k, a in enumerate(args):
            if isinstance(a, ImagePtr):
                cargs.append(((run.base + a.vaddr) & M64, 64))
            elif isinstance(a, OutBuf):
                if id(a) not in made:                        # one object passed twice is one buffer (aliasing kept)
                    made[id(a)] = run.malloc(a.size)         # writable, and undefined until the function writes it
                    for off, data in a.init:                 # except what the caller stored there first
                        run.write(made[id(a)] + off, data)
                    bufs.append((k, made[id(a)], a.size))
                cargs.append((made[id(a)], 64))
            elif isinstance(a, int):
                cargs.append((a & M64, 64))
            else:
                p = run.malloc(max(len(a), 1))
                if len(a):
                    run.write(p, bytes(a))
                else:
                    run.rheap.writable[p - run.rheap.lo] = 0
                if isinstance(a, bytearray) and len(a):
                    bufs.append((k, p, len(a)))
                cargs.append((p, 64))
        raw = run.call(entry, cargs, check_state=(state == "check"))
        changes = _state_changes(run) if state == "report" else []
        text = None
        region = run.find(raw)
        if raw and region is not None and region.name in ("image", "heap"):
            try:
                text = run.cstr(raw, 4096)
            except EmulationError:
                text = None                                  # not a readable, defined, terminated string
        finals = []
        for k, p, n in bufs:
            data, dd = run.read_shadow(p, n)
            if isinstance(args[k], bytearray) and dd != _ones(n):
                raise EmulationError("buffer argument %d ends partly undefined" % k)
            finals.append((_defined_only(data, dd), bytes(dd)))
        printed = (b"", b"")
        if run.sinks is not None:
            sk = run.sinks
            if sk["stdio"] and sk[1]:
                raise EmulationError("the call printed to stdout through stdio and through write(2): the order "
                                     "of the two depends on stdio's buffering")
            printed = (bytes(sk["stdio"] or sk[1]), bytes(sk[2]))
        outs.append((raw, text, finals, changes, [k for k, _p, _n in bufs], printed))
    (raw_a, text_a, finals_a, changes_a, keys, printed_a), (raw_b, text_b, finals_b, changes_b, _k, printed_b) = outs
    if finals_a != finals_b or changes_a != changes_b or printed_a != printed_b:
        raise EmulationError("the two runs disagree on what the call wrote (it depends on an address, poison "
                             "or an implementation-defined detail)")
    value = raw_a if raw_a == raw_b else None
    value32 = (raw_a & M32) if (raw_a & M32) == (raw_b & M32) else None
    cstr = text_a if text_a is not None and text_a == text_b else None
    if not finals_a and not changes_a and not any(printed_a) and value is None and value32 is None \
            and cstr is None:
        raise EmulationError("the two runs disagree (the result depends on an address, poison or an "
                             "implementation-defined detail)")
    for k, (data, dd) in zip(keys, finals_a):
        if isinstance(args[k], OutBuf):
            args[k].data, args[k].defined = data, dd
        else:
            args[k][:] = data
    return CallResult(value, value32, cstr, changes_a, printed_a[0], printed_a[1])


def main(argv=None):
    """Guarded offline header/export inventory for one or more supplied ELF files."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="native_image.py",
        description="inspect native ELF image metadata offline; no emulation is started",
    )
    parser.add_argument("images", nargs="+", help="local ELF image")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if not UNICORN_AVAILABLE:
        print("native_image: unicorn engine not available", file=sys.stderr)
        return 2
    failed = False
    for path in args.images:
        try:
            with open(path, "rb") as handle:
                data = handle.read(MAX_ELF + 1)
            if len(data) > MAX_ELF:
                raise EmulationError("image exceeds size cap")
            img = load(data, macho=True)
            print(path, img.arch, "problem=%s" % img.problem, sorted(img.exports()))
        except (OSError, EmulationError, ValueError, OverflowError) as exc:
            print(f"native_image: {path}: {exc}", file=sys.stderr)
            failed = True
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
