#!/usr/bin/env python3
"""KB-7: the Dalvik opcode remainder of the dex micro-VM in dex_chain_codec.py, each part exact or declining.

dex_chain_codec.VM calls this module from a handful of narrow hooks (the float branch of the binops, long-to-float,
sget/sput, new-instance, the opcode fall-through, the top of _invoke and one library hook in _invoke). Without this
module the VM behaves exactly as before. With it:

  1. FLOAT / DOUBLE exactly as Dalvik and Java (JLS 15.17, 4.2.4, 5.1.3; the Dalvik bytecode reference):
     add/sub/mul/div/rem-float and -double (and /2addr) in IEEE-754 round-to-nearest-even, a float result rounded
     to float32 after EVERY operation; rem is C fmod (truncating quotient, the sign of the dividend); division by
     zero gives +-inf or NaN and never throws; NaN and infinity propagate. Before, any NaN or infinite operand or
     result and any division by zero declined. long-to-float rounds once from the exact 64-bit integer (before, a
     value of 2**53 or more declined). Floats are raw 32-bit patterns in registers and doubles 64-bit patterns in
     a register pair, exactly as the VM already held ints and longs.
     NaN: the payload of a NaN an operation produces differs by CPU (ARM's default NaN 0x7fc00000, x86's
     0xffc00000), so the VM holds every produced NaN as the canonical pattern and EVERY observation of a NaN's raw
     bits declines (Float.floatToRawIntBits, Double.doubleToRawLongBits). Every other observation of a NaN is
     defined by Java (comparisons and the cmpl/cmpg bias, NaN->0 narrowing, floatToIntBits' canonical 0x7fc00000).
  2. JAVA LIBRARY METHODS: Float.floatToIntBits / floatToRawIntBits / intBitsToFloat / compare / isNaN / isInfinite /
     isFinite / valueOf / hashCode / sum / min / max and the Float box's floatValue / doubleValue / intValue /
     longValue / isNaN; the same for Double; Math (and StrictMath) abs / min / max (int, long, float, double, with
     Java's -0.0 and NaN rules), floor / ceil / rint / sqrt (correctly rounded), round (Java 8+ semantics AND the
     Harmony floor(x + 0.5) of Android 6 and earlier: the two must agree or the call declines), floorDiv /
     floorMod, signum, copySign (a NaN sign declines), add/subtract/multiply/negate/increment/decrementExact and
     toIntExact (overflow declines, as Java throws), pow ONLY where the specification makes it exact (a zero or 1.0
     exponent; integer base and non-negative integer exponent with a representable power). Java's text of a float
     or double (String.valueOf, Float/Double.toString, StringBuilder.append, a box's toString) ONLY for NaN, the
     infinities, the signed zeros and integral values below 10^7 in magnitude ("3.0"), where every runtime Android
     ships prints the same; any other value declines (the algorithm changed between them, JDK-4511638).
  3. STATIC FIELDS AND <clinit>: a static store per VM run. A class is initialized once, in JVM first-access order
     (JLS 12.4.1: invoke-static, sget, sput, new-instance, Class.forName, a static Field read or write, a reflective
     static call), superclass first, then its encoded static_values, then its <clinit>, bounded by the VM's step
     budget. Before, sget read 0 and sput was dropped (a static seed read as 0 assembled a confident WRONG code). A
     class whose initialization does not complete in the VM (anything unmodelled or a Java exception inside its
     <clinit>) declines at that use and at every later one. A static read is answered only when something of THIS
     run stored its value (the chain's own sput or Field.set*, a <clinit> the run executed, or the class's own encoded
     static_values applied when the run initialized it): a static nothing of the run stored declines, never its
     default 0 or null (the review of the mobile fold, probe [A2s]: the VM before this module read every static as 0).
     And it is answered only when that value is the same whatever else the app ran before the chain (the VM starts
     every chain in a fresh process, the device may not): the run itself wrote it last outside any <clinit>, with no
     code the VM does not see run since (below), or every
     sput of the field is lexically inside its declaring class's <clinit>, the dex has no reflective Field.set* /
     method handle / invoke-custom, every method of
     it decodes, it declares no native method (JNI could write it), no OTHER dex of the package references a field of
     that name through an app class or writes reflectively (sibling_refs; also reflection on reflection there:
     Method.invoke beside a Field / Unsafe / java.lang.invoke name), and loadLibrary met no JNI_OnLoad. And
     (review of 4917e79) no code outside the VM's view can run: the package ships no native library (JNI_OnLoad,
     RegisterNatives or a NativeActivity may write statics with no native method declared, S4), no dex of the package
     names a class loader, DexFile or a System/Runtime load (S5: a payload the app loads can write them), and no
     member is a dex under another name; a sput whose field reference the scan cannot resolve (a subclass with
     interfaces, a class of another dex) counts as a writer of every static of its name and type (S1); and the dex
     is small enough to scan (SCAN_MAX_UNITS code units; a larger one declines the read instead). Code the VM does
     not see that runs DURING the chain (review of 5ffe7f3): System.loadLibrary of a library the package ships taints
     the store, every later static read declining (the ELF readers miss a JNI_OnLoad of a 32-bit library or one with
     no symbol size, and a library's constructors run at the load, R2); the initialization of an app class this dex
     does not define (a superclass, a Class.forName, an invoke-static or static write of a class of another dex
     member) runs a <clinit> the VM does not see, and every value the run stored before it reads as stale and
     declines (_unseen). A
     mutable object read from a static field (an array, an object, a StringBuilder, a Method or Field token, whose
     setAccessible state code may toggle, R6) built inside a <clinit> is
     answered only when no method outside that <clinit> can write into it (an interprocedural escape scan: aput/iput
     through any alias, a store into another field or array, a return, a value read reflectively (Field.get,
     Method.invoke, a method handle: an alias of every static, S7), or a library call that is not a known reader; a
     known reader is one only for a static holding a one-dimensional primitive array, keyed by its overload
     (MessageDigest.digest(byte[], int, int) writes its buffer, S3; String.valueOf(Object) and append(Object) run an
     app toString(), S6)), only while every object the store reaches was followed (a store past the walk's bound
     declines every mutable read, S2), and never in a package that holds another dex member, whose code (a caller of
     a public getter, an override of a method the object is passed to, package-private access) the scan of this dex
     does not follow (R1). The walks and analyses behind it count against the VM's step budget (_charge): the marking
     after a <clinit> walks only what was stored since the last one, the holders of an object read come from one walk
     of the store, and an escape analysis past ESCAPE_WORK instructions counts as "may write" (a quadratic walk the
     budget never saw took 28.6 s on 4,000 <clinit>s). A framework class's static reads declines, except StandardCharsets.* (as
     before), the primitive Class tokens Long.TYPE and friends and Locale.ROOT / US / ENGLISH / UK / CANADA; a
     framework sput is dropped. A <clinit> that calls anything the VM does not model fails its class (the deliberate
     trade-off: the device ran the rest of it, which may throw or write anything), except the common idioms modelled
     exactly so it completes: Class.getSimpleName / getCanonicalName of a top-level app class of this dex (no `$` in
     its name, no InnerClass / EnclosingClass / EnclosingMethod annotation: `TAG = C.class.getSimpleName()`), and
     Log.v / d / i / w / e with a known text message (an opaque int back, which declines wherever it is observed).
     The scan behind all of this (the class index, the writers, the escape analysis) depends on the dex's bytes alone
     and is kept across calls (_ci: the two most recently used dexes of at most 2 MB and 65,536 code units, keyed by
     their digest, each holding its Dex weakly, so nothing of a Dex outlives its call); the escape analysis is decoded
     only when a mutable static is read.
  4. REFLECTION: Class.forName of a binary name ART accepts AND a class certain to exist (the running dex's own, one of
     the APK root's classes.dex, classes2.dex, ... the app class loader opens, a core framework class; a class only an
     assets/*.dex or a nested dex defines is loaded by a loader the app builds, if at all, R4; anything else may throw
     ClassNotFoundException, the hook-framework probe, and the VM takes no catch path) initializes the class (one of
     another dex member runs a <clinit> the VM does not see: _unseen); getDeclaredMethod / getMethod resolved UNIQUELY,
     at the lookup itself (a lookup with no invoke after it is the NoSuchMethodException probe, R5), over every
     declared method of that name (a native or abstract overload included; getMethod only for a public method declared
     in the class; every parameter Class known; never <init>), Method.invoke with ART's access check (public member
     of a public class, setAccessible(true), the caller's own class, or package access), the receiver an instance of
     the declaring class with no override in between, reference arguments that certainly fit, Java's unboxing and
     widening, and the box of the declared return type; getDeclaredField / getField (a public field of the class
     itself), Field.get / getInt / getLong / getFloat / getDouble / getBoolean / getByte / getShort / getChar / set /
     setInt / setLong / setBoolean / setFloat / setDouble on static fields (the same access check; a final static is
     never set), Class.getName of a class certain to exist, Object.getClass, const-class of a class certain to exist
     (another throws NoClassDefFoundError there). Anything else declines.
  5. OTHER OPCODES AND TEXT: monitor-enter / monitor-exit (one thread: no value changes; a null or a monitor not held
     declines); StringBuilder.append(boolean) "true"/"false", append(null) "null", append(Object) of a box as Java
     renders it, String.valueOf(Object) of null or a box.
  6. FRAMEWORK CLASSES, CLASS LOADERS AND FIELDS (the dexfloat-residuals fix; the two residuals the KB-7 rule paragraph
     left open, each a WRONG plain under the judged key on the tree before, and the shapes its adversarial pass found
     beside them). A class is the framework's (_framework) only when it is under a boot class path package
     (_FRAMEWORK: java, javax, android, dalvik, sun, libcore, org.json) and NO dex of the delivery defines it
     (_defined: the running dex, the other dex members, assets/*.dex too, and in the split reading every dex of the
     bundle). Lkotlin/, Lkotlinx/, Landroidx/ and Landroid/support/ (_APP_LIBS) are never the framework's: every app
     ships them in its own dexes (before, kotlin.Holder of classes2.dex was the framework's and its constructor a
     no-op). A class some dex of the delivery defines is the app's: its body runs where this dex has it, and anything
     else of it declines, as for any app class (R3). Under a boot package (_boot_shadow) a device's class loaders ask
     the boot class path first, so a device runs the boot copy where its boot class path holds the class: a body, an
     entry, a <clinit> or a static of such a class declines, and so does every static read the whole-dex scan would
     decide in that delivery (_shadows). Class.forName(name, initialize, loader) loads through `loader`: a null one is
     the bootstrap loader (only a core framework class or an array of one loads; an app class is
     ClassNotFoundException), any other one the VM cannot prove: both decline (_forname_loader; before, the loader was
     ignored). A class the base VM models by the END of its name (StringBuilder, String, Integer, Long, Character,
     Boolean) is modelled only when it is that java.lang class (_suffix_guard; java.lang.MyInteger.valueOf was
     Integer.valueOf). An instance field this run never wrote reads Java's default only when it is a field of a
     class of this dex (iget_unset; `new android.graphics.Point(42, 43).x` read 0: the base VM's constructor no-op),
     and a field an object holds under two field references of the dex declines (_no_alias: the VM keys an object's
     fields by reference, a device by the field, so Base.<init> writing n through Base's reference and a read through
     Sub's gave 0, and a later write through Sub's left Base's reference the earlier value; the VM before this module
     alike). The modelled constructor of SecretKeySpec, IvParameterSpec or Random run on an app subclass's object
     declines (_spec_guard: a device's Cipher.init asks the key for its bytes through getEncoded(), Random(long) calls
     setSeed(long), either of which the subclass may override). The independent review of the fix closed, the same way,
     the shapes it found the same on the tree before: a constructor no model takes declines but Object's
     (init_catchall: Throwable's constructors call fillInStackTrace(), ArrayList(Collection) c.toArray(), ArrayList(-1)
     throws, java.lang.Fictional is no class); every boot package counts for _boot_shadow (_BOOT_PKGS: org.xml,
     org.w3c, org.xmlpull, ...); a field no class of the chain declares declines (NoSuchFieldError); invoke-super runs
     only when no class between the caller and the reference's class declares the method (_super_target_ok); an
     instance method on a null receiver declines (_null_ref; an entry's frame of None stands for an unknown receiver
     and is not one); Object.getClass of a framework object declines (_runtime_class_known: a factory's subclass);
     check-cast passes only a value the VM certainly holds an instance of (check_cast, a hook in VM._exec: a Y cast to
     an unrelated X went on, where a device throws ClassCastException; an array's element type is not held, so an
     array to any array type passes).
     The split reading keeps the base VM's semantics but these restrictions (_base_invoke with the 1-argument forName's
     existence check, split_body, split_reflect_access, base_sget, the field reads).
  Also, each a restriction found while building this (the VM's own model was wrong there, and now declines): a native
  method whose signature carries a float or double (FP registers); an invoke-virtual whose receiver's class overrides
  the method, or whose class chain leaves this dex before the method's class (the VM does not dispatch virtually);
  BigInteger / AtomicInteger / AtomicLong / AtomicBoolean (the `endswith("Integer;")` branch claimed BigInteger.valueOf
  and truncated it to 32 bits); a box's unboxing method called through another box class (a check-cast the VM does not
  model would have thrown); StringBuilder.append(char[]/CharSequence, int, int) (the range was ignored), insert(int,
  int/long) (a character was inserted), an append of an object whose Java text is not modelled (its Python repr was
  appended); String/StringBuilder.charAt, substring, setCharAt, insert, setLength and indexOf outside the range Java
  accepts (Python wrapped a negative index or clamped); String.valueOf(Object) of an array; new StringBuilder(null) or
  of a negative capacity; Integer.parseInt of a text Java refuses (Python's int() took whitespace, underscores,
  0x/0o/0b prefixes and any size, then wrapped it to 32 bits); System.loadLibrary of a library the package does not
  ship; a class two dex members define (the device loads one copy); a call of an app class's method or constructor
  with no body in this dex, and new-instance of an app class this dex does not define (a class of another dex member:
  the base VM made its constructor a no-op, so a field the constructor sets read 0, a WRONG plain under the judged key,
  R3; it also matched an app class to String/Integer/Long by the end of its name), but where the base VM's native path
  takes the call.

THE SPLIT READING (split_bundle.SplitVM) runs on the base VM's semantics: a VM class that sets `dex_float_base =
True` gets none of the new models above (no float specials, Math/Float/Double, reflection tokens, <clinit>, Java text,
monitors or const-class; long-to-float and the float binops as the base VM computes them), because a code reached
through them would land under the split reading's own keys without the `+dex-*` suffix below, the reflection tokens
are not the `_MethTok` SplitVM._reflect resolves (Class.forName also refused a class of another split), and the static
store is per VM, while a cross-split call runs in a VM of its own. One restriction applies there too (base_sget): a
static read declines, where the base VM read 0, except the framework statics modelled here (StandardCharsets, X.TYPE,
the ASCII Locales) and a static of type android.content.Context, which reads as a ContextRef, the stand-in for the
app's Context: the split model answers getApplicationInfo for any receiver, as a device does for every Context of the
app, and every observation that could tell a null from a Context (a comparison, a hash, its text) declines, since a
Context static nothing of the run stored may be null on the device. Day 26's judged readSplit opens with sget-object
Release.ctx. A static write is dropped there, as before.

NEVER-WRONG / the key. Everything above is exact or declines. And a code that could be computed only through
something new here is never answered under the judged key: the VM records which new capability families a run used
(FLOAT for the float specials, long-to-float, the Java math/Float/Double models and float text; STATIC for static
reads from the store; REFLECT for the new reflection; OPS for monitor-enter/exit, Log.* and the new text of booleans,
null and boxes; B-249: TEXT for the StringBuilder/String methods of the B-249 block, CROSSDEX for a pure static of
another classpath dex member, by invoke-static or reflection), `note()` keeps them per code, and dex_chain_codec.answer() adds `key_suffix()` to its key and route:
`mobile.codec/analysis+dex-float` (and `+dex-ops`, `+dex-reflect`, `+dex-static`, sorted), an unsure pick until the
judge accepts that exact name. The suffix is the UNION of the families of every run that produced one of the codes
(review of 4917e79, S10: a featureless debug entry and a real chain that read a decoy default through the store gave
one code, and the intersection of the old rule dropped +dex-static: a plain decoy under the judged key). A family used
inside a <clinit> counts from the chain's first static read on (a <clinit> reaches the chain only through the statics),
so a chain that reads no static keeps the base VM's key, as it computes the base VM's code. No saved Mobile delivery
records any family, so no saved answer moves.

Loadable the way a live fix is: imports only the standard library, and reaches dex_chain_codec's own classes
through the VM it is handed (the module copy that built the VM), so it works from the armed export, a worktree or a
module loaded by file path.
"""
import hashlib
import math
import struct
import sys
import weakref
from fractions import Fraction

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
F_NAN = 0x7FC00000
D_NAN = 0x7FF8000000000000

FLOAT = "dex-float"
STATIC = "dex-static"
REFLECT = "dex-reflect"
OPS = "dex-ops"          # the other exact models new here: monitor-enter/exit, Java text of booleans, null and boxes

ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_STATIC = 0x8
ACC_FINAL = 0x10
ACC_NATIVE = 0x100
ACC_INTERFACE = 0x200
NO_INDEX = 0xFFFFFFFF

INVOKE_STATIC = (0x71, 0x77)
INVOKE_VIRTUAL = (0x6e, 0x72, 0x74, 0x78)


def _s8(x):
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def _s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def _s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def _s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


# ====================================================================== access to dex_chain_codec's own classes
# Nothing of this module is stored ON the VM: an attribute added to a VM instance after __init__ (or a read of its
# __dict__) moves CPython 3.12 off the VM's inline attribute values, and `self.steps`, which the interpreter loop reads
# and writes on every instruction, became about twice as slow (the chains ran 5 to 10 % slower). The per-run state
# lives here instead, keyed weakly by the VM.
_GLOBALS = weakref.WeakKeyDictionary()         # VM class -> the globals of the dex_chain_codec copy that defines it
_GLAST = (None, None)                          # (the VM class of the last _G call, its globals): the hot path
_VMSTATE = weakref.WeakKeyDictionary()         # VM -> _VS
_NO_VM = (lambda: None, None)
_LAST = _NO_VM                                 # (a weak reference to the VM of the last _vs call, its _VS): the hooks'
#                                                hot path. Weak, and cleared when that VM goes, so it keeps no Dex alive
#                                                after a call (review of 5ffe7f3: the last VM's Dex, 80 MB, was kept).
_UNSET = object()


class _VS:
    __slots__ = ("feat", "cfeat", "st", "mon")

    def __init__(self):
        self.feat = None
        self.cfeat = None        # families used inside a <clinit> (they count from the chain's first static read on)
        self.st = None
        self.mon = None


def _vm_gone(ref):
    global _LAST
    if _LAST[0] is ref:
        _LAST = _NO_VM


def _vs(vm):
    global _LAST
    last = _LAST
    if last[0]() is vm:
        return last[1]
    s = _VMSTATE.get(vm)
    if s is None:
        s = _VMSTATE[vm] = _VS()
    _LAST = (weakref.ref(vm, _vm_gone), s)
    return s


def _G(vm):
    """The globals of the dex_chain_codec copy that built `vm` (its _Decline, _Box, _Obj, ... classes): those of the
    class in its MRO that defines the interpreter loop. A subclass may override run() in a module of its own
    (split_bundle's SplitVM), whose globals hold none of those classes: there `type(vm).run.__globals__` was
    split_bundle's, every decline of this module raised KeyError, and every split-bundle run that touched it was lost."""
    global _GLAST
    t = type(vm)
    last = _GLAST
    if last[0] is t:
        return last[1]
    g = _GLOBALS.get(t)
    if g is None:
        for k in t.__mro__:
            kg = getattr(k.__dict__.get("run"), "__globals__", None)
            if kg is not None and kg.get("VM") is k and "_Decline" in kg:
                g = kg
                break
        else:
            g = t.run.__globals__
        _GLOBALS[t] = g
    _GLAST = (t, g)
    return g


def _base(vm):
    """True for a VM class that sets `dex_float_base = True` (split_bundle.SplitVM): the hooks then behave as the base
    VM did, except base_sget (see the module docstring, THE SPLIT READING). Read from the class each time, never
    cached by class: split_bundle makes a new SplitVM class for every tier it runs."""
    return getattr(type(vm), "dex_float_base", False) is True


def _decline(vm, why):
    raise _G(vm)["_Decline"](why)


def _charge(vm, n):
    """Count `n` units of this module's own work (objects a walk of the static store visits, instructions an escape
    analysis reads) against the VM's step budget, as the interpreter counts its instructions: dex_chain_codec's
    TOTAL_STEPS then bounds them too (review of 5ffe7f3: thousands of <clinit>s made a quadratic walk the budget never
    saw, 28.6 s for one call). Past the budget the run declines, as an interpreted step past it does."""
    if n:
        vm.steps += n
        if vm.steps > vm.max_steps:
            _decline(vm, "step budget")


def _feat(vm, fam):
    s = _vs(vm)
    st = s.st
    if st is not None and st.depth:
        # inside a <clinit>: what it computes reaches the chain only through a static the chain reads, so the family
        # counts for the code from such a read on (_static_feat); a chain that reads none computes the base VM's code
        if s.cfeat is None:
            s.cfeat = set()
        s.cfeat.add(fam)
        return
    if s.feat is None:
        s.feat = set()
    s.feat.add(fam)


def _static_feat(vm):
    """A static read by the chain: STATIC, and every family a <clinit> of this run used (inside a <clinit> it is
    only a family of the <clinit>'s, counted when the chain reads a static in turn)."""
    s = _vs(vm)
    st = s.st
    if st is not None and st.depth:
        if s.cfeat is None:
            s.cfeat = set()
        s.cfeat.add(STATIC)
        return
    if s.feat is None:
        s.feat = set()
    s.feat.add(STATIC)
    if s.cfeat:
        s.feat |= s.cfeat


# ====================================================================== 1. float / double core (pure, exact)
def f32(bits):
    return struct.unpack("<f", struct.pack("<I", bits & M32))[0]


def f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & M64))[0]


def f32_bits(v):
    """The float32 bit pattern of the Python float v, rounded to nearest even (C's (float) cast, which is what
    struct uses); a finite value beyond float32's range is the signed infinity it rounds to; NaN is canonical."""
    if v != v:
        return F_NAN
    try:
        return struct.unpack("<I", struct.pack("<f", v))[0]
    except OverflowError:
        return 0xFF800000 if v < 0 else 0x7F800000


def f64_bits(v):
    if v != v:
        return D_NAN
    return struct.unpack("<Q", struct.pack("<d", v))[0]


def is_nan32(bits):
    bits &= M32
    return (bits & 0x7F800000) == 0x7F800000 and (bits & 0x007FFFFF) != 0


def is_nan64(bits):
    bits &= M64
    return (bits & 0x7FF0000000000000) == 0x7FF0000000000000 and (bits & 0x000FFFFFFFFFFFFF) != 0


_FB = {0xa6: ("f", "add"), 0xa7: ("f", "sub"), 0xa8: ("f", "mul"), 0xa9: ("f", "div"), 0xaa: ("f", "rem"),
       0xab: ("d", "add"), 0xac: ("d", "sub"), 0xad: ("d", "mul"), 0xae: ("d", "div"), 0xaf: ("d", "rem"),
       0xc6: ("f", "add"), 0xc7: ("f", "sub"), 0xc8: ("f", "mul"), 0xc9: ("f", "div"), 0xca: ("f", "rem"),
       0xcb: ("d", "add"), 0xcc: ("d", "sub"), 0xcd: ("d", "mul"), 0xce: ("d", "div"), 0xcf: ("d", "rem")}


def _ieee(kind, a, b):
    """(result, special) of one IEEE-754 double operation on Python floats a, b, exactly as Java defines it.
    `special` is True when an operand or the result is NaN or infinite, or a divisor is zero (the cases the VM
    declined before this module)."""
    special = not (math.isfinite(a) and math.isfinite(b))
    if kind == "add":
        r = a + b
    elif kind == "sub":
        r = a - b
    elif kind == "mul":
        r = a * b
    elif kind == "div":
        if b == 0.0:
            special = True
            if a != a or a == 0.0:
                r = math.nan                                   # 0/0 and NaN/0
            else:                                              # x/+-0: infinity, sign = sign(a) xor sign(b)
                neg = (math.copysign(1.0, a) < 0) != (math.copysign(1.0, b) < 0)
                r = -math.inf if neg else math.inf
        else:
            r = a / b                                          # Python: inf on overflow, 0 on underflow, no raise
    else:                                                      # rem: Java's % on floats is C fmod
        if a != a or b != b or math.isinf(a) or b == 0.0:
            special = True
            r = math.nan
        elif math.isinf(b):
            r = a                                              # finite % +-inf is the dividend (keeps -0.0)
        else:
            r = math.fmod(a, b)                                # exact; the sign of the dividend
    return r, special or not math.isfinite(r)


def arith(op, x, y):
    """(result bits, is_wide, special) for a float/double binop (23x or /2addr). A float operation is done in
    double and rounded to float32 once: double rounding is innocuous for + - * / because 53 >= 2*24 + 2
    (Figueroa), and fmod is exact in any precision, so the result is the correctly rounded float32 Java gives."""
    typ, kind = _FB[op]
    if typ == "f":
        r, special = _ieee(kind, f32(x), f32(y))
        bits = f32_bits(r)
        return bits, False, special or not math.isfinite(f32(bits))     # a finite double may overflow float32
    r, special = _ieee(kind, f64(x), f64(y))
    return f64_bits(r), True, special


def long_to_f32_bits(v):
    """Java's (float) of a signed 64-bit long: ONE round-to-nearest-even from the exact integer (a cast through
    double would round twice and can be off by one ulp above 2**53)."""
    v = _s64(v)
    if v == 0:
        return 0
    neg = v < 0
    m = -v if neg else v
    n = m.bit_length()
    if n > 24:
        shift = n - 24
        q = m >> shift
        rem = m & ((1 << shift) - 1)
        half = 1 << (shift - 1)
        if rem > half or (rem == half and (q & 1)):
            q += 1
        f = math.ldexp(float(q), shift)                         # q <= 2**24: exact in double and in float32
    else:
        f = float(m)
    return f32_bits(-f if neg else f)


def d2i(v):
    """Java narrowing of a float/double value to int (NaN -> 0, saturate, else truncate toward zero)."""
    if v != v:
        return 0
    if v >= 2147483647.0:
        return 2147483647
    if v <= -2147483648.0:
        return -2147483648
    return int(v)


def d2l(v):
    if v != v:
        return 0
    if v >= 9223372036854775807.0:
        return 9223372036854775807
    if v <= -9223372036854775808.0:
        return -9223372036854775808
    return int(v)


def j_floor(x):
    if not math.isfinite(x) or x == 0.0:
        return x
    return float(math.floor(x))


def j_ceil(x):
    if not math.isfinite(x) or x == 0.0:
        return x
    r = float(math.ceil(x))
    return -0.0 if r == 0.0 and x < 0 else r                    # ceil(-0.5) is -0.0 in Java


def j_rint(x):
    if not math.isfinite(x) or x == 0.0:
        return x
    return math.copysign(float(round(x)), x)                    # round half even; rint(-0.4) is -0.0


def j_sqrt(x):
    if x != x or x < 0:
        return math.nan
    return math.sqrt(x)                                         # IEEE: correctly rounded; sqrt(-0.0) is -0.0


def j_round(x, is_float):
    """Math.round: Java 8+ (floor(x + 1/2) exactly, NaN -> 0, saturating) and Harmony's (Android 6 and earlier)
    (narrow) floor(x + 0.5) with the addition in the argument's own precision. Returns None when they differ (the
    device's runtime decides, so the VM declines)."""
    lo, hi = (-(1 << 31), (1 << 31) - 1) if is_float else (-(1 << 63), (1 << 63) - 1)
    if x != x:
        return 0
    if math.isinf(x):
        exact = hi if x > 0 else lo
    else:
        exact = max(lo, min(hi, math.floor(Fraction(x) + Fraction(1, 2))))
    if is_float:
        s = f32(arith(0xa6, f32_bits(x), f32_bits(0.5))[0])
        old = d2i(j_floor(s))
    else:
        s = x + 0.5
        old = d2l(j_floor(s))
    return exact if exact == old else None


def j_pow_exact(x, y):
    """Math.pow ONLY where the Java specification fixes the result exactly (Math.pow is otherwise within 1 ulp, and
    the device's libm decides): a zero exponent is 1.0; an exponent of 1.0 is the base itself; and "if both arguments
    are integers, then the result is exactly equal to the mathematical result ... if that result can in fact be
    represented exactly as a double value" (finite integers, the exact power checked to be a double). Kept to a
    NON-NEGATIVE exponent, where the result is an integer: the case fdlibm (StrictMath, and the libm Android ships)
    states it always returns exactly ("pow(integer,integer) always returns the correct integer provided it is
    representable"); a negative exponent's fraction is left out. None for anything else (the VM declines). Bounded:
    the exact power has at most about 1100 bits."""
    if y == 0.0:
        return 1.0
    if y == 1.0:
        return x
    if not (math.isfinite(x) and math.isfinite(y)) or x != math.floor(x) or y != math.floor(y) or y < 0:
        return None
    n = int(y)
    if x == 0.0:
        return -0.0 if (math.copysign(1.0, x) < 0 and n & 1) else 0.0
    b = int(x)
    if abs(b) == 1:
        return float(b if n & 1 else 1)
    if n * abs(b).bit_length() > 1100:
        return None
    exact = b ** n
    try:
        r = float(exact)                                       # int -> float: correctly rounded (CPython)
    except OverflowError:
        return None
    if not math.isfinite(r) or int(r) != exact:
        return None                                            # not representable: only within 1 ulp in Java
    return r


def j_min(a, b):
    """Math.min on floats/doubles: NaN if either is NaN, -0.0 below +0.0."""
    if a != a:
        return a
    if b != b:
        return b
    if a == 0.0 and b == 0.0:
        return a if math.copysign(1.0, a) < 0 else b
    return a if a <= b else b


def j_max(a, b):
    if a != a:
        return a
    if b != b:
        return b
    if a == 0.0 and b == 0.0:
        return b if math.copysign(1.0, a) < 0 else a
    return a if a >= b else b


def _canon32(bits):
    return F_NAN if is_nan32(bits) else bits & M32


def _canon64(bits):
    return D_NAN if is_nan64(bits) else bits & M64


def j_compare(a, b, ca, cb):
    """Float.compare / Double.compare: numeric order, then the signed order of the canonical bits (so -0.0 <
    +0.0 and NaN above everything, equal to itself)."""
    if a < b:
        return -1
    if a > b:
        return 1
    return (ca > cb) - (ca < cb)


# ====================================================================== VM hooks: float opcodes
def binop_float(vm, op, x, y):
    """The VM's float/double binop (dex_chain_codec._binop/_binop2 `if op in _FBIN`). (bits, is_wide)."""
    if _base(vm):
        return _G(vm)["_float_arith"](op, x, y)       # the base VM's fail-closed arithmetic
    if not isinstance(x, int) or not isinstance(y, int):
        _decline(vm, "float binop on a non-number register")
    bits, wide, special = arith(op, x, y)
    if special:
        _feat(vm, FLOAT)
    return bits, wide


def l2f(vm, x):
    """long-to-float (0x85) for any long, exactly."""
    if not isinstance(x, int):
        _decline(vm, "long-to-float on a non-number register")
    v = _s64(x)
    if _base(vm):                               # the base VM: fail closed from 2**53 (a double rounding there)
        if abs(v) >= (1 << 53):
            _decline(vm, "long-to-float precision")
        return _G(vm)["_f32_bits"](float(v))
    if abs(v) >= (1 << 53):                     # the range the VM declined before: new
        _feat(vm, FLOAT)
    return long_to_f32_bits(v)


# ====================================================================== 2. Float / Double / Math library models
def _params(vm, shorty, args, static):
    """The Java argument values of an invoke by its shorty (a long/double occupies two Dalvik slots; its value is
    in the first). Declines on a missing shorty, a short argument list or a primitive that is not a number."""
    if not isinstance(shorty, str) or not shorty:
        _decline(vm, "library overload needs the method's proto")
    vals = []
    i = 0 if static else 1
    for p in shorty[1:]:
        if i >= len(args):
            _decline(vm, "argument count")
        v = args[i]
        if p != "L" and not isinstance(v, int):
            _decline(vm, "primitive argument is not a number")
        vals.append(v)
        i += 2 if p in "JD" else 1
    if i != len(args):
        _decline(vm, "argument count")
    return vals


def _ret_float(vm, shorty, v):
    """A Python float returned as the shorty's F or D register value."""
    r = shorty[0]
    if r == "F":
        return f32_bits(v)
    if r == "D":
        return f64_bits(v)
    _decline(vm, "return type")


def _float_lib(vm, op, cls, name, shorty, args):
    G = _G(vm)
    Box = G["_Box"]
    isf = cls == "Ljava/lang/Float;"
    t = "F" if isf else "D"
    if op in INVOKE_STATIC:
        p = _params(vm, shorty, args, True)
        if isf:
            if name in ("floatToIntBits", "hashCode") and shorty == "IF":
                return True, _s32(_canon32(p[0]))
            if name == "floatToRawIntBits" and shorty == "IF":
                if is_nan32(p[0]):
                    _decline(vm, "floatToRawIntBits of a NaN: the payload depends on the CPU")
                return True, _s32(p[0])
            if name == "intBitsToFloat" and shorty == "FI":
                return True, p[0] & M32
            if name == "compare" and shorty == "IFF":
                return True, j_compare(f32(p[0]), f32(p[1]), _s32(_canon32(p[0])), _s32(_canon32(p[1])))
            if name in ("isNaN", "isInfinite", "isFinite") and shorty == "ZF":
                v = f32(p[0])
                return True, int(v != v if name == "isNaN" else (math.isinf(v) if name == "isInfinite"
                                                                  else math.isfinite(v)))
            if name == "valueOf" and shorty == "LF":
                return True, Box("F", p[0] & M32)
            if name == "sum" and shorty == "FFF":
                return True, arith(0xa6, p[0], p[1])[0]
            if name in ("min", "max") and shorty == "FFF":
                fn = j_min if name == "min" else j_max
                return True, f32_bits(fn(f32(p[0]), f32(p[1])))
            if name == "toString" and shorty == "LF":
                t = float_text(p[0], True)
                if t is None:
                    _decline(vm, "Float.toString: Java's text of this value differs between runtimes")
                return True, t
            return False, None
        if name == "toString" and shorty == "LD":
            t = float_text(p[0], False)
            if t is None:
                _decline(vm, "Double.toString: Java's text of this value differs between runtimes")
            return True, t
        if name == "doubleToLongBits" and shorty == "JD":
            return True, _canon64(p[0])
        if name == "doubleToRawLongBits" and shorty == "JD":
            if is_nan64(p[0]):
                _decline(vm, "doubleToRawLongBits of a NaN: the payload depends on the CPU")
            return True, p[0] & M64
        if name == "longBitsToDouble" and shorty == "DJ":
            return True, p[0] & M64
        if name == "compare" and shorty == "IDD":
            return True, j_compare(f64(p[0]), f64(p[1]), _s64(_canon64(p[0])), _s64(_canon64(p[1])))
        if name in ("isNaN", "isInfinite", "isFinite") and shorty == "ZD":
            v = f64(p[0])
            return True, int(v != v if name == "isNaN" else (math.isinf(v) if name == "isInfinite"
                                                              else math.isfinite(v)))
        if name == "valueOf" and shorty == "LD":
            return True, Box("D", p[0] & M64)
        if name == "hashCode" and shorty == "ID":
            b = _canon64(p[0])
            return True, _s32(b ^ (b >> 32))
        if name == "sum" and shorty == "DDD":
            return True, arith(0xab, p[0], p[1])[0]
        if name in ("min", "max") and shorty == "DDD":
            fn = j_min if name == "min" else j_max
            return True, f64_bits(fn(f64(p[0]), f64(p[1])))
        return False, None
    # an instance method of the box: the receiver must be a box of exactly this type
    recv = args[0] if args else None
    if not (isinstance(recv, Box) and recv.t == t):
        _decline(vm, "%s.%s receiver is not a %s box" % (cls, name, t))
    if not isinstance(shorty, str) or len(shorty) != 1 or len(args) != 1:
        _decline(vm, "%s.%s shape" % (cls, name))
    v = f32(recv.v) if isf else f64(recv.v)
    if name == "floatValue":
        return True, (recv.v & M32) if isf else f32_bits(v)
    if name == "doubleValue":
        return True, f64_bits(v)
    if name == "intValue":
        return True, d2i(v)
    if name == "longValue":
        return True, d2l(v) & M64
    if name == "shortValue":
        return True, _s16(d2i(v))
    if name == "byteValue":
        return True, _s8(d2i(v))
    if name == "isNaN":
        return True, int(v != v)
    if name == "isInfinite":
        return True, int(math.isinf(v))
    if name == "hashCode":
        if isf:
            return True, _s32(_canon32(recv.v))
        b = _canon64(recv.v)
        return True, _s32(b ^ (b >> 32))
    if name == "toString":
        t = float_text(recv.v, isf)
        if t is None:
            _decline(vm, "%s.toString: Java's text of this value differs between runtimes" % cls)
        return True, t
    return False, None


def _exact(vm, v, wide):
    lo, hi = (-(1 << 63), (1 << 63) - 1) if wide else (-(1 << 31), (1 << 31) - 1)
    if v < lo or v > hi:
        _decline(vm, "Math.*Exact overflow (Java throws ArithmeticException)")
    return v & M64 if wide else v


def _math_lib(vm, op, name, shorty, args):
    if op not in INVOKE_STATIC:
        return False, None
    p = _params(vm, shorty, args, True)
    sig = shorty
    if name == "abs":
        if sig == "II":
            return True, _s32(abs(_s32(p[0])))                 # abs(MIN_VALUE) is MIN_VALUE
        if sig == "JJ":
            return True, abs(_s64(p[0])) & M64
        if sig == "FF":
            return True, (F_NAN if is_nan32(p[0]) else p[0] & 0x7FFFFFFF)
        if sig == "DD":
            return True, (D_NAN if is_nan64(p[0]) else p[0] & 0x7FFFFFFFFFFFFFFF)
        return False, None
    if name in ("min", "max"):
        if sig == "III":
            a, b = _s32(p[0]), _s32(p[1])
            return True, (min if name == "min" else max)(a, b)
        if sig == "JJJ":
            a, b = _s64(p[0]), _s64(p[1])
            return True, (min if name == "min" else max)(a, b) & M64
        fn = j_min if name == "min" else j_max
        if sig == "FFF":
            return True, f32_bits(fn(f32(p[0]), f32(p[1])))
        if sig == "DDD":
            return True, f64_bits(fn(f64(p[0]), f64(p[1])))
        return False, None
    if name == "pow" and sig == "DDD":
        r = j_pow_exact(f64(p[0]), f64(p[1]))
        if r is None:
            _decline(vm, "Math.pow: only the cases the Java specification makes exact are modelled")
        return True, f64_bits(r)
    if name in ("floor", "ceil", "rint", "sqrt") and sig == "DD":
        fn = {"floor": j_floor, "ceil": j_ceil, "rint": j_rint, "sqrt": j_sqrt}[name]
        return True, f64_bits(fn(f64(p[0])))
    if name == "round":
        if sig == "IF":
            r = j_round(f32(p[0]), True)
        elif sig == "JD":
            r = j_round(f64(p[0]), False)
        else:
            return False, None
        if r is None:
            _decline(vm, "Math.round: Java 8 and Harmony (Android <= 6) round this value differently")
        return True, (r if sig == "IF" else r & M64)
    if name in ("floorDiv", "floorMod"):
        # the overloads java.lang.Math declares: floorDiv(int,int), (long,long), (long,int)->long;
        # floorMod(int,int), (long,long), (long,int)->int
        if sig not in (("III", "JJJ", "JJI") if name == "floorDiv" else ("III", "JJJ", "IJI")):
            return False, None
        x = _s32(p[0]) if sig[1] == "I" else _s64(p[0])
        y = _s32(p[1]) if sig[2] == "I" else _s64(p[1])
        if y == 0:
            _decline(vm, "Math.%s by zero (Java throws)" % name)
        r = x // y if name == "floorDiv" else x % y               # Python: floor division / sign of divisor
        return True, (_s32(r) if sig[0] == "I" else r & M64)
    if name == "signum":
        if sig == "FF":
            v = f32(p[0])
            return True, (p[0] & M32) if (v != v or v == 0.0) else f32_bits(math.copysign(1.0, v))
        if sig == "DD":
            v = f64(p[0])
            return True, (p[0] & M64) if (v != v or v == 0.0) else f64_bits(math.copysign(1.0, v))
        return False, None
    if name == "copySign":
        if sig == "FFF":
            if is_nan32(p[1]):
                _decline(vm, "Math.copySign with a NaN sign is unspecified")
            return True, (p[0] & 0x7FFFFFFF) | (p[1] & 0x80000000)
        if sig == "DDD":
            if is_nan64(p[1]):
                _decline(vm, "Math.copySign with a NaN sign is unspecified")
            return True, (p[0] & 0x7FFFFFFFFFFFFFFF) | (p[1] & 0x8000000000000000)
        return False, None
    if name in ("addExact", "subtractExact", "multiplyExact"):
        if sig not in (("III", "JJJ", "JJI") if name == "multiplyExact" else ("III", "JJJ")):
            return False, None                       # multiplyExact(long,int) is the one mixed overload
        a = _s32(p[0]) if sig[1] == "I" else _s64(p[0])
        b = _s32(p[1]) if sig[2] == "I" else _s64(p[1])
        r = a + b if name == "addExact" else (a - b if name == "subtractExact" else a * b)
        return True, _exact(vm, r, sig[0] == "J")
    if name in ("negateExact", "incrementExact", "decrementExact"):
        if sig not in ("II", "JJ"):
            return False, None
        a = _s32(p[0]) if sig == "II" else _s64(p[0])
        r = -a if name == "negateExact" else (a + 1 if name == "incrementExact" else a - 1)
        return True, _exact(vm, r, sig == "JJ")
    if name == "toIntExact" and sig == "IJ":
        return True, _exact(vm, _s64(p[0]), False)
    return False, None


# ====================================================================== 3. class index, static fields, <clinit>
class _CInfo:
    __slots__ = ("desc", "acc", "sup", "sf", "inst", "sv_off", "clinit", "vmeth", "dmeth", "ifaces", "annot",
                 "ifs", "has_default")

    def __init__(self, desc):
        self.desc = desc
        self.acc = 0
        self.sup = None
        self.sf = []            # [(fkey, access)] in class_data order (static_values apply in this order)
        self.inst = []          # [(fkey, access)]
        self.sv_off = 0
        self.clinit = None
        self.vmeth = set()      # {(name, proto_idx)} of declared virtual methods
        self.dmeth = []
        self.ifaces = False     # the class_def lists interfaces (JVM field lookup visits them before the superclass)
        self.annot = True       # its annotations make it a member/local/anonymous class, or do not read (_nested_marked)
        self.ifs = None         # its direct superinterfaces (type descriptors), or None when the list does not read
        self.has_default = False    # an interface that declares a default method (a virtual method with code)


def _ref(obj):
    """A weak reference to `obj` (a strong one for an object that takes none)."""
    try:
        return weakref.ref(obj)
    except TypeError:
        return lambda: obj


class _CI:
    """Per-dex class index: class_defs with superclass, access, static and instance fields, static_values, the
    <clinit>, declared methods with their access flags. A function of the dex's bytes alone: built once per bytes
    (_ci caches it across the Dex objects dex_chain_codec builds for every call). It holds the Dex it reads WEAKLY
    (_ci points it at the Dex of the call that uses it), so a cached index keeps none of a Dex's code lists alive after
    the call (review of 5ffe7f3: 80 MB kept per cached dex of 2M code units)."""

    def __init__(self, dex):
        self._dref = _ref(dex)
        self.cls = {}
        self.dup = set()
        self.macc = {}          # midx -> access flags of every encoded method
        self.direct = set()     # midx of every direct method (static, private, constructor)
        self.facc = {}          # fkey -> (access, is_static, declaring desc)
        self.natives = False
        self._fid = {}
        self._res = {}          # (field index, static) -> resolve()'s answer
        self._sget = {}         # field index -> sget's target (cls, ftype, name, fkey or None)
        self._scan = None
        self._mut = {}
        self._decl = {}
        self._outside = _UNSET
        for c in range(getattr(dex, "cls_size", 0) or 0):     # a stand-in dex without class_defs: an empty index
            try:
                self._one(c)
            except Exception:
                continue

    @property
    def dex(self):
        d = self._dref()
        if d is None:                     # never inside a call: _ci points the index at the call's own Dex first
            raise RuntimeError("the dex of this class index is gone")
        return d

    def fid(self, i):
        """(class desc, type desc, name) of field_ids[i], or None."""
        r = self._fid.get(i)
        if r is None and i not in self._fid:
            d = self.dex
            try:
                if d.field_off and i < d.field_size:
                    o = d.field_off + i * 8
                    r = (d.type_str(d._u2(o)), d.type_str(d._u2(o + 2)), d.string(d._u4(o + 4)))
            except Exception:
                r = None
            self._fid[i] = r
        return r

    def _one(self, c):
        d = self.dex
        o = d.cls_off + c * 32
        cidx, acc, sup, data, sv = d._u4(o), d._u4(o + 4), d._u4(o + 8), d._u4(o + 24), d._u4(o + 28)
        ifoff = d._u4(o + 12)
        desc = d.type_str(cidx)
        sfl, ifl, dml, vml = [], [], [], []
        if data:
            p = data
            ns, p = d._uleb(p)
            ni, p = d._uleb(p)
            nd, p = d._uleb(p)
            nv, p = d._uleb(p)
            for lst, n in ((sfl, ns), (ifl, ni)):
                fi = 0
                for _ in range(n):
                    di, p = d._uleb(p)
                    fi += di
                    fa, p = d._uleb(p)
                    lst.append((fi, fa))
            for lst, n in ((dml, nd), (vml, nv)):
                mi = 0
                for _ in range(n):
                    di, p = d._uleb(p)
                    mi += di
                    ma, p = d._uleb(p)
                    _, p = d._uleb(p)
                    lst.append((mi, ma))
        for _m, ma in dml + vml:
            if ma & ACC_NATIVE:
                self.natives = True             # whatever is trusted of the class below: JNI is in the dex
        mo = d.meth_off
        own = {d._u2(mo + m * 8) for m, _ in dml + vml}            # class type index of each method (no text)
        owners = ({d.type_str(t) for t in own} if own != {cidx} else {desc}) if own else set()
        trusted = True
        if owners and owners != {desc}:
            # a malformed (test-fixture) class_def whose class_idx does not name its own methods' class: take the
            # class its methods say, and trust no superclass link of it
            if len(owners) != 1:
                return
            desc = next(iter(owners))
            trusted = False
        if desc in self.cls:
            self.dup.add(desc)
            return
        ci = _CInfo(desc)
        ci.acc = acc
        ci.ifaces = bool(ifoff) or not trusted
        ci.ifs = _interfaces(d, ifoff) if trusted else None
        ci.has_default = bool(acc & ACC_INTERFACE) and any(m in d.code for m, _a in vml)
        ci.annot = not trusted or _nested_marked(d, d._u4(o + 20))
        if trusted and sup != NO_INDEX:
            s = d.type_str(sup)
            ci.sup = s if s != desc else None
        for lst, out, static in ((sfl, ci.sf, True), (ifl, ci.inst, False)):
            for fi, fa in lst:
                t = self.fid(fi)
                if t is None or t[0] != desc:
                    return                      # a field the class does not own: nothing of this class is trusted
                fkey = (t[0], t[2], t[1])       # (declaring class, name, type)
                out.append((fkey, fa))
                self.facc[fkey] = (fa, static, desc)
        for m, ma in dml + vml:
            self.macc[m] = ma
        for m, ma in dml:
            ci.dmeth.append(m)
            self.direct.add(m)
            if d.string(d._u4(mo + m * 8 + 4)) == "<clinit>":
                ci.clinit = m
        for m, ma in vml:
            ci.vmeth.add((d.string(d._u4(mo + m * 8 + 4)), d._u2(mo + m * 8 + 2)))
        ci.sv_off = sv
        self.cls[desc] = ci

    def resolve(self, fid, static=True):
        """The fkey of a field reference (JVM field resolution: the class named, then its superclasses), or None
        when it cannot be resolved inside this dex (framework superclass, interface, ambiguity, wrong kind)."""
        k = (fid, static)
        r = self._res.get(k, _UNSET)
        if r is _UNSET:
            r = self._res[k] = self._resolve(fid, static)
        return r

    def outside_refs(self):
        """Why code outside the VM's view may run, from this dex's own references (a class loader, DexFile, a
        System/Runtime load), or None. Cached with the index."""
        if self._outside is _UNSET:
            d = self.dex
            self._outside = _loading_refs(d.d, lambda: (d.meth(i) for i in range(getattr(d, "meth_size", 0) or 0)))
        return self._outside

    def _resolve(self, fid, static):
        t = self.fid(fid)
        if t is None:
            return None
        cls, ftype, name = t
        c, seen = cls, set()
        while c is not None and c in self.cls and c not in seen:
            if c in self.dup:
                return None
            seen.add(c)
            info = self.cls[c]
            for fkey, _a in info.sf:
                if fkey[1] == name and fkey[2] == ftype:
                    return fkey if static else None
            for fkey, _a in info.inst:
                if fkey[1] == name and fkey[2] == ftype:
                    return None if static else fkey
            if info.ifaces:
                return None                     # superinterfaces come before the superclass: not modelled
            c = info.sup
        return None

    def static_values(self, info, vm):
        """[value] for the class's first static fields, from its encoded static_values array (an unmodelled kind is
        the _UNKNOWN marker, which declines when read)."""
        if not info.sv_off:
            return []
        d = self.dex
        n, p = d._uleb(info.sv_off)
        out = []
        for _ in range(n):
            v, p = _encoded_value(d, p, vm)
            out.append(v)
        return out


_UNKNOWN = object()
_NESTED_MARKS = frozenset(("Ldalvik/annotation/InnerClass;", "Ldalvik/annotation/EnclosingClass;",
                           "Ldalvik/annotation/EnclosingMethod;"))


def _interfaces(d, interfaces_off):
    """A class_def's direct superinterfaces (type descriptors), [] for none, None when the list cannot be read."""
    if not interfaces_off:
        return []
    try:
        return [d.type_str(d._u2(interfaces_off + 4 + 2 * i)) for i in range(d._u4(interfaces_off))]
    except Exception:
        return None


def _iface_unseen(vm, ci, info):
    """True when initializing the class may run a superinterface's <clinit> the VM does not run. ART initializes, with
    a class (never with an interface), every superinterface that declares a default method, its superinterfaces first
    (JLS 12.4.2 step 7; ClassLinker's InitializeDefaultInterfaceRecursive), and the VM runs an interface's <clinit> only
    at a use of its own static. So: an app superinterface another dex member defines (or none here does), or one of this
    dex with a default method and a <clinit>, at any depth; a list that does not read counts too."""
    if info.acc & ACC_INTERFACE:
        return False
    if info.ifs is None:
        return True
    ext = _ext(vm)
    todo, seen = list(info.ifs), set()
    while todo:
        i = todo.pop()
        if i in seen or _framework(vm, i):     # (a Lkotlin/ interface of this dex is the app's: dexfloat-residuals)
            continue
        seen.add(i)
        ii = ci.cls.get(i)
        if ii is None or i in ci.dup or ii.ifs is None or (ext is not None and i in ext.get("dup", ())):
            return True
        if ii.has_default and ii.clinit is not None:
            return True
        todo.extend(ii.ifs)
    return False


def _nested_marked(d, annotations_off):
    """True when a class_def's own annotations say it is a member, local or anonymous class (its simple name is then
    not the last segment of its name), or when they cannot be read; False for no class annotations."""
    if not annotations_off:
        return False
    try:
        cls_set = d._u4(annotations_off)
        if not cls_set:
            return False
        for i in range(d._u4(cls_set)):
            item = d._u4(cls_set + 4 + 4 * i)
            t, _p = d._uleb(item + 1)                   # annotation_item: visibility, then encoded_annotation's type
            if d.type_str(t) in _NESTED_MARKS:
                return True
        return False
    except Exception:
        return True


def _encoded_value(d, p, vm):
    b = d.d[p]
    p += 1
    vt, va = b & 0x1F, b >> 5
    if vt == 0x1E:                                  # VALUE_NULL
        return 0, p
    if vt == 0x1F:                                  # VALUE_BOOLEAN
        return va & 1, p
    if vt == 0x1C:                                  # VALUE_ARRAY: skipped, unmodelled
        n, p = d._uleb(p)
        for _ in range(n):
            _, p = _encoded_value(d, p, vm)
        return _UNKNOWN, p
    if vt == 0x1D:                                  # VALUE_ANNOTATION: skipped, unmodelled
        _, p = d._uleb(p)
        n, p = d._uleb(p)
        for _ in range(n):
            _, p = d._uleb(p)
            _, p = _encoded_value(d, p, vm)
        return _UNKNOWN, p
    size = va + 1
    raw = d.d[p:p + size]
    p += size
    u = int.from_bytes(raw, "little")
    if vt == 0x00:                                  # BYTE
        return _s8(u), p
    if vt == 0x02:                                  # SHORT (sign-extended)
        return _s16(int.from_bytes(raw, "little", signed=True)), p
    if vt == 0x03:                                  # CHAR (zero-extended)
        return u & 0xFFFF, p
    if vt == 0x04:                                  # INT
        return _s32(int.from_bytes(raw, "little", signed=True)), p
    if vt == 0x06:                                  # LONG
        return int.from_bytes(raw, "little", signed=True) & M64, p
    if vt == 0x10:                                  # FLOAT: zero-extended to the right
        return (u << (8 * (4 - size))) & M32, p
    if vt == 0x11:                                  # DOUBLE: zero-extended to the right
        return (u << (8 * (8 - size))) & M64, p
    if vt == 0x17:                                  # STRING
        return d.string(u), p
    if vt == 0x18:                                  # TYPE
        return _cref(vm, d.type_str(u)) if vm is not None else ClassRef(d.type_str(u)), p
    return _UNKNOWN, p                              # METHOD_TYPE/HANDLE, FIELD, METHOD, ENUM


_CI_CACHE = {}       # digest of the dex bytes -> _CI, the _CI_KEEP most recently used: the index and the whole-dex scan
_CI_KEEP = 2         # depend on the bytes alone, and dex_chain_codec builds a new Dex for every call (codec_search makes
#                      two calls a set over the same members: review of 4917e79). Two entries, kept by recent use.
_CI_MAX_BYTES = 2 << 20      # a dex past either bound is not kept (its index and scan are rebuilt for each call): the
_CI_MAX_UNITS = 1 << 16      # cache holds at most a few MB (every Mobile delivery of Days 1-26: < 8 KB, < 1,300 units)
_LITE_KEEP = 4


def _bytes_key(data):
    """The key of the bytes-keyed caches: the length and SHA-256 of the dex, so no cache keeps the bytes alive."""
    return len(data), hashlib.sha256(data).digest()


def _cache_get(cache, key):
    """A lookup in one of the bytes-keyed caches that marks the entry most recently used; None when absent."""
    try:
        v = cache.pop(key)
    except (KeyError, TypeError):
        return None
    cache[key] = v
    return v


def _cache_put(cache, key, value, keep=_CI_KEEP):
    """An insertion into one of the bytes-keyed caches, the least recently used entries dropped past `keep` (never
    fatal)."""
    try:
        cache.pop(key, None)
        while len(cache) >= keep:
            cache.pop(next(iter(cache)), None)
        cache[key] = value
    except Exception:
        cache.clear()


def _ci(dex):
    ci = getattr(dex, "_dfl_ci", None)
    if ci is not None:
        if ci._dref() is not dex:
            ci._dref = _ref(dex)          # another Dex of the same bytes used it since: read this call's own again
        return ci
    data = getattr(dex, "d", None)
    key = None
    if type(data) is bytes and len(data) <= _CI_MAX_BYTES:
        try:
            if sum(len(v[2]) for v in dex.code.values()) <= _CI_MAX_UNITS:
                key = _bytes_key(data)
        except Exception:
            key = None
    ci = _cache_get(_CI_CACHE, key) if key is not None else None
    if ci is None:
        ci = _CI(dex)
        if key is not None:
            _cache_put(_CI_CACHE, key, ci)
    else:
        ci._dref = _ref(dex)
    dex._dfl_ci = ci
    return ci


class _St:
    """The static store of one VM run."""
    __slots__ = ("store", "init", "last", "depth", "taint", "clinit_objs", "keep", "stack", "crefs", "reach_cut",
                 "hf_ok", "cc_ok", "pre_ok", "dirty", "unseen")

    def __init__(self):
        self.store = {}
        self.init = {}
        self.last = {}             # fkey -> who stored it last: "run", "clinit", "init" (static_values), "stale" (_unseen)
        self.depth = 0
        self.taint = None
        self.unseen = None         # why code the VM does not see ran during the run (the last such point), or None
        self.clinit_objs = set()   # id() of mutable objects reachable from the store when a <clinit> ended
        self.dirty = {}            # fkeys stored since the last marking, in store order (an ordered set: only their
        #                            values are walked, _mark_clinit_objects, the same way in every process)
        self.keep = []             # strong references, so those ids are never reused
        self.stack = []            # the classes whose <clinit> is running, innermost last
        self.crefs = {}            # interned Class / Locale tokens (Java's identity: one Class object per type)
        self.reach_cut = False     # a walk of the store stopped at its bound: clinit_objs may miss objects (S2)
        self.hf_ok = set()         # fkeys whose history-free rule held in this run (it depends on the package only)
        self.cc_ok = set()         # id() of <clinit> objects whose contents check held in this run
        self.pre_ok = set()        # method indexes whose non-virtual invoke passed pre_invoke (its class initialized)


def _st(vm):
    vs = _vs(vm)
    st = vs.st
    if st is None:
        st = vs.st = _St()
    return st


def _default(ftype):
    return 0


def ensure_init(vm, desc):
    """JVM class initialization of an app class, once: superclass first, then static_values, then <clinit>. A class
    whose initialization did not complete in the VM (anything unmodelled, or a Java exception, inside its <clinit>)
    declines here and at every later use: on the device it either threw (ExceptionInInitializerError, then
    NoClassDefFoundError at each use) or ran something the VM cannot follow, so nothing after it is known."""
    st = _st(vm)
    state = st.init.get(desc)
    if state is not None:
        if state == "failed":
            _decline(vm, "class %s did not initialize in the VM" % desc)
        return                                    # done, ext, or running (a recursive request returns at once)
    ci = _ci(vm.dex)
    info = ci.cls.get(desc)
    if info is None or desc in ci.dup:
        st.init[desc] = "ext"
        if desc[:1] == "L" and not _framework(vm, desc):
            # an app class this dex does not define (another dex member's: a superclass, a Class.forName, an
            # invoke-static or a static write of it): its <clinit> runs on the device and not here (_unseen). Since the
            # dexfloat-residuals fix also a Lkotlin/ (Lkotlinx/, Landroidx/) class and a class under a framework package
            # that another dex of the delivery defines (_framework: before, kotlin.Other of classes2.dex was the
            # framework's, its <clinit> unseen, and a static the run stored read as stored: a WRONG plain)
            _unseen(vm, st, "the initialization of %s, a class this dex does not define, runs a <clinit> the VM does "
                    "not see" % desc)
        return
    if _boot_shadow(desc):
        # this dex defines a class of a boot class path package: a device initializes the boot copy where its boot
        # class path holds the class, this one only where it does not
        st.init[desc] = "failed"
        _no_shadow(vm, desc, "the initialization")
    _not_duplicated(vm, desc)
    st.init[desc] = "running"
    try:
        if info.sup is not None:
            ensure_init(vm, info.sup)             # a framework superclass is "ext"; one of another dex is _unseen (above)
        if _iface_unseen(vm, ci, info):
            # a superinterface with a default method is initialized with the class on the device, and the VM runs
            # no interface's <clinit> here (one of this dex runs only at a use of its own static)
            _unseen(vm, st, "the initialization of %s also initializes a superinterface with default methods, whose "
                    "<clinit> the VM does not run" % desc)
        vals = ci.static_values(info, vm)
    except Exception as e:
        st.taint = st.taint or "initialization of %s: %s" % (desc, str(e)[:80])
        st.init[desc] = "failed"
        _decline(vm, "class %s did not initialize: %s" % (desc, str(e)[:80]))
    for i, (fkey, _a) in enumerate(info.sf):
        if fkey not in st.store:
            st.store[fkey] = vals[i] if i < len(vals) else _default(fkey[2])
            st.dirty[fkey] = None
            if i < len(vals):
                st.last[fkey] = "init"            # the class's own encoded initial value, stored by this run's init
    if info.clinit is not None and info.clinit in vm.dex.code:
        st.depth += 1
        st.stack.append(desc)
        failed = None
        try:
            vm.run(info.clinit, [])
        except Exception as e:                    # anything unmodelled inside <clinit>, or a Java exception
            failed = e
        finally:
            st.depth -= 1
            st.stack.pop()
        if failed is not None:
            st.taint = st.taint or "<clinit> of %s: %s" % (desc, str(failed)[:80])
            st.init[desc] = "failed"
            _decline(vm, "<clinit> of %s did not complete: %s" % (desc, str(failed)[:80]))
        _mark_clinit_objects(vm, st)
    st.init[desc] = "done"


def _unseen(vm, st, why):
    """Code the VM does not see runs on the device at this point (another dex member's <clinit>). It may write any
    static of this dex: through a field reference of its own (sibling_refs names it), a method of this dex (a writer
    the history-free rule counts), reflection (sibling_refs' star), all of which _read_static already refuses for a
    value a <clinit> or static_values stored. But a value the run itself stored last was answered as stored, with no
    such check (review of 5ffe7f3, the shortcut R2 also went through): every one stored before this point is marked
    stale, and its read declines; a write after it is the run's own again."""
    st.unseen = why
    last = st.last
    for k, w in last.items():
        if w == "run":
            last[k] = "stale"
    _charge(vm, len(last))


def _mutable(vm, v):
    """An object whose contents (or state) code may change: an array, an object, a StringBuilder, and a reflection token
    (Method / Field: setAccessible toggles it; review of 5ffe7f3, R6: a token a <clinit> stored was never checked)."""
    if type(v) is int or type(v) is str or v is None:
        return False
    G = _G(vm)
    return isinstance(v, (list, G["_Obj"], G["_SB"], MethodRef, FieldRef))


def _children(vm, v):
    G = _G(vm)
    if isinstance(v, list):
        return v
    if isinstance(v, G["_Obj"]):
        return list(v.fields.values())
    return ()


REACH_LIMIT = 4096


def _reach(vm, roots, limit=REACH_LIMIT):
    """(id() -> object of every mutable object reachable from `roots`, complete). `complete` is False when the walk
    stopped at `limit` objects with more to visit: the map then misses objects, and no caller may rely on it (review
    of 4917e79, S2: a key array behind 5000 <clinit> arrays was never marked, and its contents check never ran). Its
    work is charged to the VM's step budget (_charge)."""
    out, stack = {}, list(roots)
    work = len(stack)
    try:
        while stack:
            v = stack.pop()
            if not _mutable(vm, v) or id(v) in out:
                continue
            if len(out) >= limit:
                return out, False
            out[id(v)] = v
            kids = _children(vm, v)
            work += 1 + len(kids)
            stack.extend(c for c in kids if _mutable(vm, c))
        return out, True
    finally:
        _charge(vm, work)


def _mark_clinit_objects(vm, st):
    """At the end of a <clinit>: mark every mutable object the store reaches (they may predate the chain on the device,
    _check_contents). Only the values of the statics stored since the last marking are walked, and an object marked
    before is not walked again (review of 5ffe7f3: a walk of the whole store after every <clinit>, 28.6 s for 4,000
    classes): an object newly put INTO a marked one is reachable only through it, and its holder's contents check
    covers it (a write into a held object outside its own <clinit> declines that check). The marked objects are
    bounded by REACH_LIMIT in all (past it every mutable read declines, S2), and the work is charged to the budget."""
    keys = st.dirty
    st.dirty = {}
    if st.reach_cut or not keys:
        return
    marked = st.clinit_objs
    stack = [v for v in (st.store.get(k) for k in keys) if _mutable(vm, v) and id(v) not in marked]
    work = len(keys)
    try:
        while stack:
            v = stack.pop()
            if id(v) in marked:
                continue
            if len(marked) >= REACH_LIMIT:
                st.reach_cut = True
                return
            marked.add(id(v))
            st.keep.append(v)
            kids = _children(vm, v)
            work += 1 + len(kids)
            stack.extend(c for c in kids if _mutable(vm, c) and id(c) not in marked)
    finally:
        _charge(vm, work)


_KIND_TYPES = ("IF", "JD", "L[", "Z", "B", "C", "S")


def _check_type(vm, op, ftype, get):
    """The sget/sput opcode must match the field's type, as the verifier requires."""
    if ftype[:1] not in _KIND_TYPES[op - (0x60 if get else 0x67)]:
        _decline(vm, "sget/sput kind does not match the field type %s" % ftype)


def _coerce(op, ftype, v, get):
    k = op - (0x60 if get else 0x67)
    if k == 0:
        return (v & M32) if ftype == "F" else _s32(v)
    if k == 1:
        return v & M64
    if k == 2:
        return v
    if k == 3:
        return v & 1
    if k == 4:
        return _s8(v)
    if k == 5:
        return v & 0xFFFF
    return _s16(v)


_PRIM_TYPE = {"Ljava/lang/Boolean;": "Z", "Ljava/lang/Byte;": "B", "Ljava/lang/Character;": "C",
              "Ljava/lang/Short;": "S", "Ljava/lang/Integer;": "I", "Ljava/lang/Long;": "J",
              "Ljava/lang/Float;": "F", "Ljava/lang/Double;": "D", "Ljava/lang/Void;": "V"}
_ASCII_LOCALES = ("ROOT", "US", "ENGLISH", "UK", "CANADA")


class LocaleRef:
    """Locale.ROOT / US / ENGLISH / UK / CANADA: every one formats digits, hex and case in ASCII exactly as the
    VM's String.format and toUpperCase do."""
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


def _framework_sget(vm, op, cls, name, ftype):
    G = _G(vm)
    if op == 0x62 and cls == "Ljava/nio/charset/StandardCharsets;" and name in G["_CHARSETS"]:
        return G["_Charset"](name)                                      # as before this module
    if op == 0x62 and name == "TYPE" and cls in _PRIM_TYPE and ftype == "Ljava/lang/Class;":
        return _cref(vm, _PRIM_TYPE[cls])                               # Long.TYPE: the primitive class token
    if op == 0x62 and cls == "Ljava/util/Locale;" and name in _ASCII_LOCALES:
        return _lref(vm, name)
    # a framework static, or one of an app class this dex does not define (no store holds it; the sput of one is dropped)
    _decline(vm, "static field %s->%s of a class this dex does not define is not modelled" % (cls, name))


_CONTEXT = "Landroid/content/Context;"


class ContextRef:
    """The split reading's stand-in for the app's Context, read from a Context static nothing of the run stored
    (base_sget). It is good only as the receiver of a framework call the split model answers alike for every Context
    of the app (getApplicationInfo; a device answers it with the app's one ApplicationInfo, and on a null it throws:
    no code at all). Every observation that could tell a null from a Context declines, since such a static may be null
    on the device: a comparison (if-eqz, if-nez, if-eq, ...), a hash, a truth value, its text, a number of it."""
    __slots__ = ("_no",)

    def __init__(self, decline):
        self._no = decline

    def _refuse(self, *_a, **_k):
        raise self._no("the app's Context, read from a static nothing of the run stored: it may be null on the device")

    __eq__ = __ne__ = __lt__ = __le__ = __gt__ = __ge__ = _refuse
    __hash__ = __bool__ = __str__ = __format__ = __int__ = __index__ = __float__ = __len__ = __iter__ = _refuse

    def __repr__(self):
        return "<the app's Context (split reading)>"


def base_sget(vm, op, fid):
    """sget* in a VM on the base VM's semantics (split_bundle.SplitVM; the module docstring, THE SPLIT READING): the
    base VM read every static as 0, a WRONG plain where the app had set it (review 2 of the mobile fold, probe [A2s]).
    Here it declines, except a framework static modelled here (_framework_sget: StandardCharsets as the base VM had
    it, X.TYPE, the ASCII Locales; any other framework static declines) and an sget-object of a static of type
    android.content.Context, which reads as a ContextRef, the stand-in for the app's Context: the split model answers
    getApplicationInfo for any receiver, as a device does for every Context of the app, and anything that could tell a
    null from a Context declines. Day 26's judged readSplit opens with sget-object Release.ctx."""
    dex = vm.dex
    fl = dex.field(fid)
    if not fl:
        _decline(vm, "sget: field not in the dex")
    cls, name = fl
    try:
        ftype = dex.type_str(dex._u2(dex.field_off + fid * 8 + 2))
    except Exception:
        _decline(vm, "sget: the field's type is not in the dex")
    if cls.startswith(_FRAMEWORK_KB7):
        if not _framework(vm, cls):
            # a Lkotlin/ class, or a class of a framework package a dex of the delivery defines (dexfloat-residuals):
            # never the framework's static; a Lkotlin/ static declined here before too (_framework_sget models none)
            _decline(vm, "static %s->%s: a class a dex of the delivery defines, or one of a library every app ships "
                     "itself, is never the framework's" % (cls, name))
        return _framework_sget(vm, op, cls, name, ftype)
    if op == 0x62 and ftype == _CONTEXT:
        return ContextRef(_G(vm)["_Decline"])
    _decline(vm, "static %s->%s in the split reading: its value is not modelled there (the base VM read 0)"
             % (cls, name))


def sget(vm, op, fid):
    """sget* (0x60-0x66): the value, JVM-initializing the declaring class first. Declines when the value could
    differ on the device (see the module docstring)."""
    if _base(vm):
        return base_sget(vm, op, fid)
    ci = _ci(vm.dex)
    tgt = ci._sget.get(fid)
    if tgt is None:
        t = ci.fid(fid)
        if t is None:
            _decline(vm, "sget: field not in the dex")
        cls, ftype, name = t
        tgt = ci._sget[fid] = (cls, ftype, name, ci.resolve(fid, static=True) if cls in ci.cls else None)
    cls, ftype, name, fkey = tgt
    if cls not in ci.cls:
        if not _framework(vm, cls):
            # (dexfloat-residuals) a class another dex of the delivery defines, or a Lkotlin/ one: never a framework
            # static (_framework_sget would decline it but for the framework statics it models)
            _decline(vm, "static field %s->%s of a class this dex does not define is not modelled" % (cls, name))
        return _framework_sget(vm, op, cls, name, ftype)
    if cls.startswith(_BOOT_PKGS):
        _no_shadow(vm, cls, "the static %s" % name)
    if fkey is None:
        _decline(vm, "sget: %s->%s does not resolve to a static field of this dex" % (cls, name))
    _check_type(vm, op, ftype, True)
    ensure_init(vm, fkey[0])
    v = _read_static(vm, ci, fkey)
    _static_feat(vm)
    return _coerce(op, ftype, v, True)


def _read_static(vm, ci, fkey):
    st = _st(vm)
    if st.taint:
        _decline(vm, "static store tainted: %s" % st.taint)
    if fkey not in st.last:
        # nothing of this run stored it (no chain write, no <clinit> write, no static_values entry): its default 0 or
        # null holds only if no code outside the VM's view ever writes it, and the VM never reads a value it did not
        # see stored (review of the mobile fold, probe [A2s])
        _decline(vm, "static %s->%s: nothing of this run stored it" % (fkey[0], fkey[1]))
    v = st.store.get(fkey, 0)
    if v is _UNKNOWN:
        _decline(vm, "static value of %s->%s is an unmodelled encoded value" % (fkey[0], fkey[1]))
    if st.init.get(fkey[0]) == "running" and (not st.stack or st.stack[-1] != fkey[0]):
        # a class still being initialized, read from ANOTHER class's <clinit>: a circular initialization, whose
        # values depend on which class the app touched first
        _decline(vm, "circular class initialization through %s->%s" % (fkey[0], fkey[1]))
    ext = _ext(vm)
    if ext is not None and (ext["star"] or fkey[1] in ext["names"]):
        _decline(vm, "static %s->%s may be written by code in another dex of the package" % (fkey[0], fkey[1]))
    who = st.last.get(fkey)
    if who == "stale":
        _decline(vm, "static %s->%s: the run stored it, and since then %s (it may have written it)"
                 % (fkey[0], fkey[1], st.unseen))
    # the run's own last write decides only in the chain's own code: a <clinit> may have run on the device before
    # that write (so a read inside a <clinit> always takes the history-free rule below)
    if (who != "run" or st.depth > 0) and fkey not in st.hf_ok:
        why = _history_free(vm, ci, fkey)
        if why is not None:
            _decline(vm, "static %s->%s: %s" % (fkey[0], fkey[1], why))
        st.hf_ok.add(fkey)
    if type(v) is not int and type(v) is not str and _mutable(vm, v):
        if st.reach_cut:
            _decline(vm, "static %s->%s: the store holds more objects than the VM follows (%d), so which of them a "
                     "<clinit> built is not known" % (fkey[0], fkey[1], REACH_LIMIT))
        if id(v) in st.clinit_objs and id(v) not in st.cc_ok:
            _check_contents(vm, ci, st, v)
            st.cc_ok.add(id(v))
    return v


def _history_free(vm, ci, fkey):
    """None when a static's value cannot depend on what ran before the chain (its only writer is its own class's
    <clinit>, and nothing the VM cannot see may write it), else the reason. A function of the package alone, so
    _read_static keeps its verdict for the run."""
    sc = _scan(vm)
    if sc.big:
        return "the dex is too large to scan for its writers (%d code units > %d)" % (sc.units, SCAN_MAX_UNITS)
    if sc.reflect_set:
        return "the dex writes fields reflectively"
    if sc.blind:
        return "a method of the dex could not be decoded (its writers are unknown)"
    if ci.natives:
        return "the dex declares native methods (JNI may write statics)"
    why = _outside(vm)
    if why:
        return why
    sh = _shadows(vm)
    if sh:
        return ("the delivery defines %s, a class of the boot class path's package: a device may run the boot copy's "
                "code, which the scan of this dex cannot read" % sh[0])
    if (fkey[1], fkey[2]) in sc.unresolved:
        # a sput the scan cannot resolve (a subclass with interfaces, a class of another dex) may resolve to this
        # static on the device (review of 4917e79, S1)
        return "a sput of a field %s of type %s does not resolve in the scan (it may write this one)" % (fkey[1],
                                                                                                         fkey[2])
    info = ci.cls[fkey[0]]
    if sc.writers.get(fkey, set()) - {info.clinit}:
        return "it is written outside its <clinit>: its value depends on what ran before"
    return None


_NATIVE_LOADS = frozenset(("load", "loadLibrary", "load0", "loadLibrary0", "nativeLoad"))
_LOADER_MARKS = (b"ClassLoader", b"DexFile")


def _loading_refs(data, meths):
    """Why a dex can run code the VM does not see, or None: it names a class loader or DexFile anywhere (a type, a
    method, or a class name for reflection), or calls System/Runtime load/loadLibrary (`meths` yields the (class,
    name) of its method_ids, asked only when a raw search of the bytes finds a load at all)."""
    try:
        for m in _LOADER_MARKS:
            if m in data:
                return "the package names %s: it may load code the VM does not see, which may write statics" \
                       % m.decode()
        if b"load" in data:
            for c, nm in meths():
                if nm in _NATIVE_LOADS and c in ("Ljava/lang/System;", "Ljava/lang/Runtime;"):
                    return "the package calls %s.%s: native code it loads may write statics" % (c[1:-1].replace(
                        "/", "."), nm)
    except Exception:
        return "the package's references could not be read"
    return None


def _outside(vm):
    """Why code outside the VM's view may run before the chain (and write statics), or None: what attach() found in
    the package (a native library, a dex under another name, another dex member's loading references), this dex's own
    loading references, or native code the VM was handed (review of 4917e79, S4/S5)."""
    dex = vm.dex
    why = getattr(dex, "_dfl_pkg", None)
    if why:
        return why
    why = _ci(dex).outside_refs()
    if why:
        return why
    if getattr(vm, "native_syms", None) or getattr(vm, "native_arm", None):
        return "the VM was handed a native library: its code (JNI_OnLoad, RegisterNatives) may write statics"
    return None


def attach(dex, so_members=(), ext=None):
    """dex_chain_codec.codes_in_dex_ex, before the entries run: what the package holds beside this dex (`ext`, from
    package_info, or None for a bare dex) and whether native libraries came with it."""
    if ext is not None:
        dex._dfl_ext = ext
    dex._dfl_defs = None              # the delivery's classes (_defined) are read again for this call
    why = None
    if so_members:
        why = ("the package ships a native library: its code (JNI_OnLoad, RegisterNatives, a NativeActivity) may "
               "write statics before the chain")
    elif ext is not None:
        why = ext.get("outside")
    dex._dfl_pkg = why


def _ext(vm):
    """What the rest of the package holds, set by dex_chain_codec.analysis_codes_ex (package_info), or None when the VM
    was handed a bare dex: {"names": field names the OTHER dex members reference through an app class (a sput there
    may resolve to a static of this dex, directly or through a subclass defined there), "star": they write fields
    reflectively, declare a native method or do not parse, "defined": the classes they define, "loadable": the classes
    the device's app class loader certainly finds (those of the APK root's classes.dex, classes2.dex, ... in order:
    Class.forName from the app's code, _exists), "multi": the package holds another dex member (its code is outside the
    escape scan of this dex), "libs": the file names of the package's native libraries (System.loadLibrary),
    "outside": why code the VM does not see may run (a native library, a dex under another name, another member's
    loading references), or None}."""
    return getattr(vm.dex, "_dfl_ext", None)


_CLASSPATH_MAX = 256


def _classpath_dexes(files):
    """The dex members a device's app class loader opens: the APK root's classes.dex, then classes2.dex, classes3.dex,
    ... in order, up to the first one missing (ART's multidex rule). A dex anywhere else (assets/payload.dex, a nested
    path) is loaded only by a class loader the app builds, if at all, so Class.forName from the app's code may throw
    ClassNotFoundException for its classes (review of 5ffe7f3, R4)."""
    out = []
    if isinstance(files, dict):
        for i in range(1, _CLASSPATH_MAX + 1):
            v = files.get("classes.dex" if i == 1 else "classes%d.dex" % i)
            if not isinstance(v, (bytes, bytearray)) or not v:
                break
            out.append(bytes(v))
    return out


def package_info(files, dex_datas):
    """Per dex member of the package (in dex_chain_codec._dex_members order): the dict _ext describes."""
    libs = set()
    outside = None
    if isinstance(files, dict):
        dexset = None
        for k, v in files.items():
            if not isinstance(k, str):
                continue
            if k.endswith(".so"):
                libs.add(k.rsplit("/", 1)[-1])
                if v and outside is None:
                    outside = ("the package ships a native library (%s): its code (JNI_OnLoad, RegisterNatives, a "
                               "NativeActivity) may write statics before the chain" % k)
            elif isinstance(v, (bytes, bytearray)) and v[:4] in (b"dex\n", b"dey\n"):
                if dexset is None:
                    dexset = {bytes(x) for x in dex_datas}
                if bytes(v) not in dexset and outside is None:
                    outside = "the package holds a dex under another name (%s), which it may load" % k
    multi = len(set(dex_datas)) > 1
    loadable = set()
    if multi:
        # (with one dex member, the classpath's classes are the running dex's own, which _exists reads first)
        for data in _classpath_dexes(files):
            s = _lite_summary(data)
            if s is not None:                     # a classpath dex that does not parse: none of its classes is known
                loadable |= s["defined"]
    sib = sibling_refs(dex_datas) if multi else [None] * len(dex_datas)
    out = []
    for s in sib:
        e = s if s is not None else {"names": set(), "star": False, "defined": set(), "dup": set(), "outside": None}
        e["libs"] = libs
        e["outside"] = outside or e.get("outside")
        e["loadable"] = loadable
        e["multi"] = multi
        e["datas"] = dex_datas            # B-249: the package's dex members (CROSSDEX parses the one it needs)
        out.append(e)
    return out


def sibling_refs(dex_datas):
    """Per dex of a package: the dict to hand codes_in_dex_ex as `_ext` (see _ext). A field reference in one dex is a
    possible writer of a static the scan of another dex cannot see, so it is counted by NAME whenever its class is an
    app class (not a framework one): conservative across subclass resolution."""
    info = [_lite_summary(data) for data in dex_datas]
    # (dexfloat-residuals) a field reference through a class of a framework package counts when a dex of the package
    # defines that class (it may be a subclass of an app class there, and its field resolve to a static of this dex), and
    # through a Lkotlin/ (Lkotlinx/, Landroidx/) class always: neither is the framework's
    pkg_defined = set()
    for s in info:
        if s is not None:
            pkg_defined |= s["defined"]
    out = []
    for i, mine in enumerate(info):
        ext = {"names": set(), "star": mine is None, "defined": set(), "dup": set(), "outside": None}
        for j, other in enumerate(info):
            if j == i or dex_datas[j] == dex_datas[i]:
                continue                         # an identical copy (the runner's files hold a member twice) is one
            if other is None:
                ext["star"] = True
                continue
            if other["writers"] or other["natives"]:
                ext["star"] = True
            if other["outside"] and ext["outside"] is None:
                ext["outside"] = other["outside"]
            ext["defined"] |= other["defined"]
            for cls, name in other["frefs"]:
                if not cls.startswith(_FRAMEWORK) or cls.startswith(_APP_LIBS) or cls in pkg_defined:
                    ext["names"].add(name)
        if mine is not None:
            # a class two dex members define: the device's class loader uses ONE copy (which one depends on the
            # member order and the loader), so this dex's copy is never run or initialized by the VM
            ext["dup"] = mine["defined"] & ext["defined"]
        out.append(ext)
    return out


_LITE_CACHE = {}      # digest of the dex bytes -> summary, the _LITE_KEEP most recently used (a package's members are
#                       summarized for every call)


def _lite_summary(data):
    key = _bytes_key(data) if type(data) is bytes and len(data) <= _CI_MAX_BYTES else None
    if key is not None:
        hit = _cache_get(_LITE_CACHE, key)
        if hit is not None:
            return hit[0]
    try:
        s = _DexLite(data).summary()
    except Exception:
        s = None
    if key is not None:
        _cache_put(_LITE_CACHE, key, (s,), _LITE_KEEP)
    return s


class _DexLite:
    """Just enough of a dex for sibling_refs: defined classes, field references, reflective writers, natives."""

    def __init__(self, data):
        self.d = data

    def _u2(self, o):
        return struct.unpack_from("<H", self.d, o)[0]

    def _u4(self, o):
        return struct.unpack_from("<I", self.d, o)[0]

    def _uleb(self, o):
        r = s_ = 0
        while True:
            b = self.d[o]
            o += 1
            r |= (b & 0x7F) << s_
            if not b & 0x80:
                return r, o
            s_ += 7

    def _str(self, i):
        off = self._u4(self._u4(60) + 4 * i)
        _, p = self._uleb(off)
        return self.d[p:self.d.index(b"\x00", p)].decode("utf-8", "replace")

    def _type(self, i):
        return self._str(self._u4(self._u4(68) + 4 * i))

    def summary(self):
        u4 = self._u4
        fsize, foff, msize, moff, csize, coff = u4(80), u4(84), u4(88), u4(92), u4(96), u4(100)
        defined = {self._type(u4(coff + 32 * c)) for c in range(csize)}
        frefs = set()
        for i in range(fsize):
            o = foff + 8 * i
            frefs.add((self._type(self._u2(o)), self._str(u4(o + 4))))
        meths = [(self._type(self._u2(moff + 8 * i)), self._str(u4(moff + 8 * i + 4))) for i in range(msize)]
        writers = any(_reflective_writer(c, nm) for c, nm in meths)
        if not writers and ("Ljava/lang/reflect/Method;", "invoke") in meths:
            # Method.invoke can reach a field writer with no method reference of it (reflection on Field.setLong,
            # Unsafe.put*, a method handle): a dex that names one of their classes writes reflectively, as _Scan rules
            # for the running dex (review of 4917e79), now for the other members too
            writers = any(m in self.d for m in _REFLECT_WRITER_MARKS)
        outside = _loading_refs(self.d, lambda: iter(meths))
        natives = False
        for c in range(csize):
            data = u4(coff + 32 * c + 24)
            if not data:
                continue
            p = data
            ns, p = self._uleb(p)
            ni, p = self._uleb(p)
            nd, p = self._uleb(p)
            nv, p = self._uleb(p)
            for _ in range(2 * (ns + ni)):
                _, p = self._uleb(p)
            for _ in range(nd + nv):
                _, p = self._uleb(p)
                acc, p = self._uleb(p)
                _, p = self._uleb(p)
                if acc & ACC_NATIVE:
                    natives = True
        return {"defined": defined, "frefs": frefs, "writers": writers, "natives": natives, "outside": outside}


def _reflective_writer(c, nm):
    """An API that can write a field without a sput the scan sees."""
    if c == "Ljava/lang/reflect/Field;":
        return nm.startswith("set") and nm != "setAccessible"
    if c in ("Lsun/misc/Unsafe;", "Ljdk/internal/misc/Unsafe;"):
        return nm.startswith(("put", "compareAnd", "getAndSet", "getAndAdd", "set"))
    return c.startswith("Ljava/lang/invoke/")


def _holders(vm, st, v):
    """The statics whose value reaches the object v, from ONE walk of the store that records each object's parents
    (review of 5ffe7f3: a walk per static for every read, quadratic in the store). Declines when the store reaches more
    than REACH_LIMIT objects (the holders are then not known); the work is charged to the VM's step budget."""
    direct = {}                  # id(object) -> the statics holding it directly
    parents = {}                 # id(object) -> {id(parent object)}
    seen = set()
    work = 0
    try:
        for k, val in st.store.items():
            work += 1
            if not _mutable(vm, val):
                continue
            direct.setdefault(id(val), []).append(k)
            stack = [val]
            while stack:
                o = stack.pop()
                if id(o) in seen:
                    continue
                if len(seen) >= REACH_LIMIT:
                    _decline(vm, "the static store reaches more objects than the VM follows (%d): the holders of the "
                             "object read are not known" % REACH_LIMIT)
                seen.add(id(o))
                kids = _children(vm, o)
                work += 1 + len(kids)
                for c in kids:
                    if _mutable(vm, c):
                        parents.setdefault(id(c), set()).add(id(o))
                        if id(c) not in seen:
                            stack.append(c)
    finally:
        _charge(vm, work)
    up, stack = {id(v)}, [id(v)]
    while stack:
        for p in parents.get(stack.pop(), ()):
            if p not in up:
                up.add(p)
                stack.append(p)
    _charge(vm, len(up))
    found = {k for i in up for k in direct.get(i, ())}
    # in the store's own order (never an order of id() values): the checks that follow, and the steps they charge
    # before one of them declines, are the same in every process
    return [k for k in st.store if k in found]


def _check_contents(vm, ci, st, v):
    """A mutable object built by a <clinit> and read through a static: no method outside that <clinit> may be able
    to write into it (else its contents depend on what ran before)."""
    ext = _ext(vm)
    if ext is not None and ext.get("multi"):
        # the package holds another dex: its code may reach the object through any method of this dex (a public getter
        # it calls, an override of a virtual method the object is passed to, package-private access, reflection), and
        # the escape scan below follows the code of this dex only (review of 5ffe7f3, R1/R1b)
        _decline(vm, "static object: the package holds another dex member, whose code the escape scan of this dex "
                 "does not follow")
    sh = _shadows(vm)
    if sh:
        _decline(vm, "static object: the delivery defines %s, a class of the boot class path's package, whose boot copy "
                 "a device may run instead of the code the escape scan reads" % sh[0])
    holders = _holders(vm, st, v)
    if not holders:
        _decline(vm, "static object with no holder")
    decl = {k[0] for k in holders}
    exempt = set()
    if len(decl) == 1:
        c = ci.cls.get(next(iter(decl)))
        if c is not None and c.clinit is not None:
            exempt.add(c.clinit)
    sc = _scan(vm)
    if sc.big:
        _decline(vm, "static object: the dex is too large to scan for its writers (%d code units > %d)"
                 % (sc.units, SCAN_MAX_UNITS))
    for k in holders:
        if (k[1], k[2]) in sc.unresolved_get:
            _decline(vm, "static object %s->%s: an sget-object of a field %s of type %s does not resolve in the scan, "
                     "and code holding what it reads may write into the object" % (k[0], k[1], k[1], k[2]))
        mut, cost = sc.contents_mutable(k, frozenset(exempt))
        _charge(vm, cost)
        if mut:
            _decline(vm, "static object %s->%s may be written outside its <clinit>" % (k[0], k[1]))


def sput(vm, op, fid, value):
    """sput* (0x67-0x6d): store into the run's static store (a framework class's static is dropped, as before)."""
    if _base(vm):
        return                                      # dropped, as the base VM did (base_sget reads no store)
    ci = _ci(vm.dex)
    t = ci.fid(fid)
    if t is None:
        _decline(vm, "sput: field not in the dex")
    cls, ftype, name = t
    if cls not in ci.cls:
        if not _framework(vm, cls):
            # a static of an app class this dex does not define: the store has no place for it (the write is dropped,
            # as before), and on the device the write initializes that class, whose <clinit> the VM does not see
            # (dexfloat-residuals: a Lkotlin/ class, and a framework package's class another dex defines, alike)
            ensure_init(vm, cls)
        return
    if cls.startswith(_BOOT_PKGS):
        _no_shadow(vm, cls, "the static %s" % name)
    fkey = ci.resolve(fid, static=True)
    if fkey is None:
        _decline(vm, "sput: %s->%s does not resolve to a static field of this dex" % (cls, name))
    _check_type(vm, op, ftype, False)
    ensure_init(vm, fkey[0])
    st = _st(vm)
    if op != 0x69 and not isinstance(value, int):
        _decline(vm, "sput of a non-number into a primitive static")
    st.store[fkey] = _coerce(op, ftype, value, False)
    st.dirty[fkey] = None
    st.last[fkey] = "run" if st.depth == 0 else "clinit"


def on_new_instance(vm, desc):
    """new-instance initializes an app class (JLS 12.4.1); a class that failed to initialize declines. An app class
    this dex does not define (another dex member's) declines here: its constructor and its <clinit> run on the device
    and not in the VM (review of 5ffe7f3, R3: the base VM's <init> catch-all made such an object empty, and a field its
    constructor sets read 0, a WRONG plain under the judged key). Since the dexfloat-residuals fix a Lkotlin/ (Lkotlinx/,
    Landroidx/) class and a framework package's class another dex of the delivery defines alike (_framework: new
    kotlin.Holder() of classes2.dex was the framework's, its constructor a no-op)."""
    _suffix_guard(vm, desc, "new-instance")       # (the split reading too: the VM makes a StringBuilder/String of it)
    if _base(vm):
        return
    if desc[:1] == "L" and not _framework(vm, desc):
        ci = _ci(vm.dex)
        if desc not in ci.cls or desc in ci.dup:
            _decline(vm, "new-instance of %s, a class this dex does not define: its constructor runs code the VM does "
                     "not see" % desc)
    ensure_init(vm, desc)


# ---------------------------------------------------------------------- the whole-dex scan (writers, escapes)
SCAN_MAX_UNITS = 1 << 18
"""Code units the whole-dex scan reads. A dex with more declines every read the history-free rule or the contents
check would decide, instead of scanning it (review of 4917e79: a 4.9 MB dex of 60,000 methods took 0.33 s a call to
scan). Every Mobile delivery of Days 1-26 has under 4,000 code units in all."""

ESCAPE_WORK = 1_000_000
"""Instructions one escape analysis (one static's contents check) reads at most; past it the object counts as
writable and the read declines. The instructions read are charged to the VM's step budget either way."""


class _WorkCut(Exception):
    """An escape analysis past ESCAPE_WORK instructions."""

_READONLY_LIB = {
    ("Ljava/lang/String;", "<init>"): 1, ("Ljava/lang/String;", "valueOf"): 0,
    ("Ljava/lang/String;", "copyValueOf"): 0,
    ("Ljava/lang/StringBuilder;", "append"): 1, ("Ljava/lang/StringBuffer;", "append"): 1,
    ("Ljava/lang/StringBuilder;", "<init>"): 1, ("Ljava/lang/StringBuffer;", "<init>"): 1,
    ("Ljava/security/MessageDigest;", "update"): 1, ("Ljava/security/MessageDigest;", "digest"): 1,
    ("Ljava/util/zip/CRC32;", "update"): 1,
    ("Ljava/util/Arrays;", "toString"): 0, ("Ljava/util/Arrays;", "hashCode"): 0,
    ("Ljava/util/Arrays;", "equals"): 0, ("Ljava/util/Arrays;", "copyOf"): 0,
    ("Ljava/util/Arrays;", "copyOfRange"): 0,
}
"""(class, method) -> the first argument slot from which the library method only READS a one-dimensional primitive
array argument (and returns nothing that aliases it). Slot 0 of an instance method is its receiver, which these may
change (StringBuilder.append, MessageDigest.update), so they start at 1. System.arraycopy reads only slot 0 (its
source). It is asked only for a static holding such an array (_lib_reads), and MessageDigest.digest only for its
digest(byte[]) overload."""

_PRIM_ARRAYS = frozenset("[" + c for c in "ZBSCIJFD")
_REFLECT_READS = frozenset((("Ljava/lang/reflect/Field;", "get"), ("Ljava/lang/reflect/Method;", "invoke")))
_REFLECT_WRITER_MARKS = (b"java/lang/reflect/Field", b"java.lang.reflect.Field", b"Unsafe", b"java/lang/invoke",
                         b"java.lang.invoke")


def _lib_reads(dex, c, nm, callee, pos, htype):
    """True only when a library call that receives an alias (at the argument slots `pos`) of the object a static of
    type `htype` holds can neither write into it nor let it reach code that can: the static holds a one-dimensional
    primitive array (no app code runs on one: it has no toString, equals, hashCode or element of its own), the method
    reads from those slots on (_READONLY_LIB), and the overload is one that reads. Anything else answers False (review
    of 4917e79: MessageDigest.digest(byte[], int, int) writes its buffer, S3; String.valueOf(Object) and
    StringBuilder.append(Object) of an app object run its toString(), which may write it, S6; a copy of an array of
    references holds the same elements)."""
    if htype not in _PRIM_ARRAYS:
        return False
    if c == "Ljava/lang/System;" and nm == "arraycopy":
        return all(j == 0 for j in pos)
    first = _READONLY_LIB.get((c, nm))
    if first is None or any(j < first for j in pos):
        return False
    if c == "Ljava/security/MessageDigest;" and nm == "digest":
        return _proto(dex, callee)[1] == ["[B"]
    return True


_K_SPUT, _K_INVOKE, _K_OPAQUE, _K_UNUSED = 1, 2, 3, 4


class _Scan:
    """Per dex (cached with its class index): every static field's sput writers, the (name, type) of every sput whose
    field reference does not resolve here, whether the dex writes fields reflectively, and, built only when a mutable
    static is read, a decoded form of every method for the escape analysis of objects held by static fields."""

    def __init__(self, dex, ci):
        self.ci = ci                 # the Dex is read through the class index (held weakly there, _CI.dex)
        self.W = _SCAN_W             # its own table: the VM's sizes 0xfa-0xff as one unit, which would misalign
        self.writers = {}            # fkey -> {midx}
        self.unresolved = set()      # (name, type) of every sput the scan cannot resolve to a static of this dex
        self.unresolved_get = set()  # (name, type) of every sget-object the scan cannot resolve (final review, aa8a367)
        self.sget_obj = {}           # fkey -> {midx: {registers loaded by sget-object}}  (the full decode)
        self.refl_obj = {}           # midx -> {registers a reflective read may load a static's object into}
        self.reflect_set = False     # a Field.set* (or a method handle, Unsafe, java.lang.invoke) anywhere
        self.reflect_call = False    # a Method.invoke anywhere (a call this scan cannot follow)
        self.blind = False           # a method this scan could not decode: its sput writers are unknown
        self._dec = None
        self._virt = None
        self._mf = {}
        self.units = 0
        for _r, _i, insns in dex.code.values():
            self.units += len(insns)
        self.big = self.units > SCAN_MAX_UNITS
        if self.big:
            return                   # every question this scan answers declines (_history_free, _check_contents)
        for midx, (_r, _i, insns) in dex.code.items():
            try:
                self._writers(midx, insns)
            except Exception:
                self.blind = True    # undecodable: its sput writers are unknown
        if self.reflect_call and not self.reflect_set:
            # Method.invoke can call a framework writer with no method reference of it in the dex (reflection on
            # Field.set*, Unsafe.put*, a method handle): a dex that names one of their classes writes reflectively
            try:
                data = dex.d
                if any(m in data for m in _REFLECT_WRITER_MARKS):
                    self.reflect_set = True
            except Exception:
                self.reflect_set = True

    @property
    def dex(self):
        return self.ci.dex

    def _writers(self, midx, insns):
        """The cheap pass: sput writers, reflective writers and calls, method handles. It sizes every instruction as
        _decode does, so the two agree on what decodes."""
        W, K = self.W, _SCAN_KIND
        n = len(insns)
        pc = 0
        while pc < n:
            u = insns[pc]
            op = u & 0xFF
            if op == 0 and u in (0x0100, 0x0200, 0x0300):
                pc += _payload_units(insns, pc, u)
                continue
            k = K[op]
            if k == _K_UNUSED:
                raise ValueError("unused opcode 0x%02x: the method's instruction stream cannot be sized" % op)
            w = W[op]
            if pc + w > n:
                raise ValueError("instruction past the end of the code")
            if op == 0x62:
                self._get_obj(insns[pc + 1])
            if k == _K_SPUT:
                self._put(midx, insns[pc + 1])
            elif k == _K_INVOKE:
                f = self._flags(insns[pc + 1])
                if f[0]:
                    self.reflect_set = True
                if f[1]:
                    self.reflect_call = True
            elif k == _K_OPAQUE:
                # invoke-polymorphic/custom, const-method-handle/type: a method handle may be a STATIC_PUT or call
                # anything, with no field or method reference this scan could see
                self.reflect_set = True
                self.reflect_call = True
            pc += w

    def _get_obj(self, fid):
        """An sget-object the scan cannot resolve (a reference through a subclass with interfaces, a class defined
        twice) may read a <clinit>-built static's object on the device, and the alias it seeds is not followed by the
        escape scan: _check_contents declines a holder of that name and type (final review of aa8a367)."""
        if self.ci.resolve(fid, static=True) is not None:
            return
        t = self.ci.fid(fid)
        if t is None:
            self.blind = True        # a field reference outside the table: what it reads is unknown
        else:
            self.unresolved_get.add((t[2], t[1]))

    def _put(self, midx, fid):
        fk = self.ci.resolve(fid, static=True)
        if fk is not None:
            self.writers.setdefault(fk, set()).add(midx)
            return
        t = self.ci.fid(fid)
        if t is None:
            self.blind = True        # a field reference outside the table: what it writes is unknown
        else:
            self.unresolved.add((t[2], t[1]))

    def _flags(self, callee):
        """(writes a field reflectively, a Method.invoke, reads a static's object reflectively) of a call target."""
        f = self._mf.get(callee)
        if f is None:
            c, nm = self.dex.meth(callee)
            f = self._mf[callee] = (_reflective_writer(c, nm), c == "Ljava/lang/reflect/Method;" and nm == "invoke",
                                    (c, nm) in _REFLECT_READS)
        return f

    @property
    def dec(self):
        """midx -> the decoded form of the method (None when it does not decode: every question about it answers
        "may write"), built on first use."""
        if self._dec is None:
            dec = {}
            for midx, (_r, _i, insns) in self.dex.code.items():
                try:
                    dec[midx] = self._decode(midx, insns)
                except Exception:
                    dec[midx] = None
            self._dec = dec
        return self._dec

    def _decode(self, midx, insns):
        dex, W = self.dex, self.W
        out = []
        n = len(insns)
        pc = 0
        while pc < n:
            u = insns[pc]
            if u in (0x0100, 0x0200, 0x0300):             # payload pseudo-instructions
                pc += _payload_units(insns, pc, u)
                continue
            op = u & 0xFF
            b1 = u >> 8
            w = W[op]
            if op in _UNUSED_OPS:
                raise ValueError("unused opcode 0x%02x: the method's instruction stream cannot be sized" % op)
            if pc + w > n:
                raise ValueError("instruction past the end of the code")
            if op >= 0xfa:
                out.append(("opaque",))
                if op <= 0xfd and pc + w < n and (insns[pc + w] & 0xFF) == 0x0c:
                    # what a method handle returns (a static getter's handle) may be a static's object (S7)
                    self.refl_obj.setdefault(midx, set()).add(insns[pc + w] >> 8)
                pc += w
                continue
            if 0x60 <= op <= 0x6d:
                if op == 0x69:
                    out.append(("escape", b1))              # sput-object: another static now holds it
                if op == 0x62:
                    fk = self.ci.resolve(insns[pc + 1], static=True)
                    if fk is not None:
                        self.sget_obj.setdefault(fk, {}).setdefault(midx, set()).add(b1)
            elif op == 0x07:
                out.append(("move", b1 & 0xF, b1 >> 4))
            elif op == 0x08:
                out.append(("move", b1, insns[pc + 1]))
            elif op == 0x09:
                out.append(("move", insns[pc + 1], insns[pc + 2]))
            elif op == 0x11:
                out.append(("return", b1))
            elif op == 0x27:
                out.append(("escape", b1))                  # throw
            elif op == 0x26:
                out.append(("mutate", b1))                  # fill-array-data writes the array
            elif 0x44 <= op <= 0x51:
                arr = insns[pc + 1] & 0xFF
                if op == 0x46:
                    out.append(("move", b1, arr))           # aget-object: an element belongs to the object
                elif op >= 0x4b:
                    out.append(("mutate", arr))
                    if op == 0x4d:
                        out.append(("escape", b1))          # stored into an array
            elif 0x52 <= op <= 0x5f:
                a, b = b1 & 0xF, b1 >> 4
                if op == 0x54:
                    out.append(("move", a, b))              # iget-object
                elif op >= 0x59:
                    out.append(("mutate", b))
                    if op == 0x5b:
                        out.append(("escape", a))           # stored into an object
            elif op in (0x24, 0x25):
                for r in self._regs(op, b1, insns, pc):
                    out.append(("escape", r))               # filled-new-array holds it
            elif 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
                regs = self._regs(op, b1, insns, pc)
                callee = insns[pc + 1]
                c, nm = dex.meth(callee)
                mr = None
                if pc + w < n and (insns[pc + w] & 0xFF) == 0x0c:
                    mr = insns[pc + w] >> 8
                    if (c, nm) in _REFLECT_READS:
                        # Field.get / Method.invoke may hand back a static's object with no sget-object this scan
                        # sees: the register is an alias of every static's object (review of 4917e79, S7)
                        self.refl_obj.setdefault(midx, set()).add(mr)
                out.append(("invoke", op, callee, regs, mr, c, nm))
            pc += max(w, 1)
        return out

    @staticmethod
    def _regs(op, b1, insns, pc):
        if op == 0x24 or 0x6e <= op <= 0x72:
            cnt = (b1 >> 4) & 0xF
            rw = insns[pc + 2]
            return [rw & 0xF, (rw >> 4) & 0xF, (rw >> 8) & 0xF, (rw >> 12) & 0xF, b1 & 0xF][:cnt]
        first = insns[pc + 2]
        return list(range(first, first + b1))

    def _virtual_targets(self, callee):
        """Every method body in the dex a virtual call through method_ids[callee] might run (same name and proto)."""
        if self._virt is None:
            self._virt = {}
            d = self.dex
            for mi in d.code:
                k = (d.mname[mi][1], d._u2(d.meth_off + mi * 8 + 2))
                self._virt.setdefault(k, []).append(mi)
        d = self.dex
        return self._virt.get((d.meth(callee)[1], d._u2(d.meth_off + callee * 8 + 2)), [])

    def contents_mutable(self, fkey, exempt):
        """(may a method outside `exempt` write into an object held by static field fkey, or let it reach code that
        can, or code this scan cannot follow; the instructions the analysis read). Memoised per dex with its cost, so a
        caller charges the same work to the VM's budget whether the answer was cached or not (the answer never depends
        on what ran before in the process). An analysis that would read more than ESCAPE_WORK instructions stops and
        counts as "may write" (review of 5ffe7f3: one analysis per static, each reading every method of the dex)."""
        if self.big:
            return True, 0
        key = (fkey, exempt)
        r = self.ci._mut.get(key)
        if r is None:
            work = [0]
            try:
                mut = self._contents_mutable(fkey, exempt, work)
            except (RecursionError, _WorkCut):
                mut = True
            r = self.ci._mut[key] = (mut, work[0])
        return r

    def _contents_mutable(self, fkey, exempt, work):
        memo = {}
        for midx in self.dec:
            if midx in exempt:
                continue
            mut, ret = self._analyze(midx, frozenset(), fkey, memo, 0, work)
            if mut:
                return True
            if ret:
                # it hands the object to its caller: fine where every caller is followed (a direct method, no
                # reflective call anywhere); a virtual method or a reflective caller is code this scan cannot see
                acc = self.ci.macc.get(midx, 0)
                if self.reflect_call or not (acc & (ACC_STATIC | ACC_PRIVATE)):
                    return True
        return False

    def _analyze(self, midx, seeds, fkey, memo, depth, work):
        """(may write into the object, returns an alias of it) for method midx when the registers `seeds` hold an
        alias on entry (its own sget-object of fkey, and what it reads reflectively, are seeds too). `work` counts the
        instructions read; past ESCAPE_WORK the analysis stops (_WorkCut)."""
        k = (midx, seeds)
        if k in memo:
            return memo[k]
        memo[k] = (False, False)                     # a recursion cycle adds nothing new
        dec = self.dec.get(midx)
        if dec is None or depth > 8:
            memo[k] = (True, True)
            return memo[k]
        al = set(seeds) | self.sget_obj.get(fkey, {}).get(midx, set()) | self.refl_obj.get(midx, set())
        htype = fkey[2]
        mut = ret = False
        for _ in range(64):
            grew = False
            work[0] += len(dec) + 1
            if work[0] > ESCAPE_WORK:
                raise _WorkCut()
            for ins in dec:
                kind = ins[0]
                if kind == "move":
                    if ins[2] in al and ins[1] not in al:
                        al.add(ins[1])
                        grew = True
                elif kind == "invoke":
                    op, callee, regs, mr, c, nm = ins[1:]
                    pos = frozenset(j for j, r in enumerate(regs) if r in al)
                    # the bodies this call may run: the method itself, and on a virtual call every body in the dex
                    # with its name and proto (an override; the VM refuses a detected one, the device runs it)
                    targets = set(self._virtual_targets(callee)) if op in INVOKE_VIRTUAL else set()
                    if callee in self.dex.code:
                        targets.add(callee)
                    for t in sorted(targets):
                        tr, ti, _ = self.dex.code[t]
                        m2, r2 = self._analyze(t, frozenset(tr - ti + j for j in pos), fkey, memo, depth + 1, work)
                        mut = mut or m2
                        if r2 and mr is not None and mr not in al:
                            al.add(mr)
                            grew = True
                    if callee in self.dex.code or not pos:
                        continue
                    # (the set the KB-7 tree read as library bodies, Lkotlin/ included: unchanged by the dexfloat-residuals
                    # fix, so the scan answers exactly as before; a delivery that defines a boot package's class declines
                    # every read this scan decides, _shadows)
                    if not c.startswith(_FRAMEWORK_KB7):
                        if not targets:
                            mut = True                      # an app method with no body (native / abstract)
                        continue
                    if not _lib_reads(self.dex, c, nm, callee, pos, htype):
                        mut = True                          # a library body: only the known readers of an array
            if not grew:
                break
        work[0] += len(dec)
        for ins in dec:
            if ins[0] in ("mutate", "escape") and ins[1] in al:
                mut = True
            elif ins[0] == "return" and ins[1] in al:
                ret = True
            elif ins[0] == "opaque" and al:
                mut = True                              # a method handle call may receive any alias it holds
        memo[k] = (mut, ret)
        return memo[k]


def _payload_units(insns, pc, u):
    """The size in code units of the payload pseudo-instruction at pc (packed-switch, sparse-switch, fill-array-data);
    IndexError on a truncated one."""
    if u == 0x0100:
        return insns[pc + 1] * 2 + 4
    if u == 0x0200:
        return insns[pc + 1] * 4 + 2
    sz = insns[pc + 2] | (insns[pc + 3] << 16)
    return (sz * insns[pc + 1] + 1) // 2 + 4


def _widths():
    w = [1] * 256
    for op in range(256):
        if op in (0x02, 0x05, 0x08):
            w[op] = 2
        elif op in (0x03, 0x06, 0x09):
            w[op] = 3
        elif op in (0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23):
            w[op] = 2
        elif op in (0x14, 0x17, 0x1b, 0x24, 0x25, 0x26):
            w[op] = 3
        elif op == 0x18:
            w[op] = 5
        elif op == 0x29:
            w[op] = 2
        elif op in (0x2a, 0x2b, 0x2c):
            w[op] = 3
        elif 0x2d <= op <= 0x3d or 0x44 <= op <= 0x6d:
            w[op] = 2
        elif 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
            w[op] = 3
        elif 0x90 <= op <= 0xaf or 0xd0 <= op <= 0xe2:
            w[op] = 2
        elif op in (0xfa, 0xfb):                     # invoke-polymorphic(/range): 45cc / 4rcc
            w[op] = 4
        elif op in (0xfc, 0xfd):                     # invoke-custom(/range): 35c / 3rc
            w[op] = 3
        elif op in (0xfe, 0xff):                     # const-method-handle / const-method-type: 21c
            w[op] = 2
    return w


_SCAN_W = _widths()
_UNUSED_OPS = frozenset(list(range(0x3e, 0x44)) + [0x73, 0x79, 0x7a] + list(range(0xe3, 0xfa)))


def _kinds():
    k = [0] * 256
    for op in range(256):
        if op in _UNUSED_OPS:
            k[op] = _K_UNUSED
        elif 0x67 <= op <= 0x6d:
            k[op] = _K_SPUT
        elif 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
            k[op] = _K_INVOKE
        elif op >= 0xfa:
            k[op] = _K_OPAQUE
    return k


_SCAN_KIND = _kinds()


def _scan(vm):
    ci = _ci(vm.dex)
    if ci._scan is None:
        ci._scan = _Scan(ci.dex, ci)
    return ci._scan


# ====================================================================== 4. reflection
class ClassRef:
    """A java.lang.Class: the type descriptor (a primitive is its one letter)."""
    __slots__ = ("desc",)

    def __init__(self, desc):
        self.desc = desc


class MethodRef:
    __slots__ = ("desc", "name", "params", "public_only", "accessible")

    def __init__(self, desc, name, params, public_only):
        self.desc = desc
        self.name = name
        self.params = params          # [type descriptor] or None when the Class[] was not all known
        self.public_only = public_only
        self.accessible = False


class FieldRef:
    __slots__ = ("fkey", "acc", "static", "accessible")

    def __init__(self, fkey, acc, static):
        self.fkey = fkey
        self.acc = acc
        self.static = static
        self.accessible = False


def _cref(vm, desc):
    """The one ClassRef of `desc` in this VM run (Java: `Long.TYPE == Long.TYPE`, `forName(x) == forName(x)`)."""
    st = _st(vm)
    r = st.crefs.get(("c", desc))
    if r is None:
        r = st.crefs[("c", desc)] = ClassRef(desc)
    return r


def _lref(vm, name):
    st = _st(vm)
    r = st.crefs.get(("l", name))
    if r is None:
        r = st.crefs[("l", name)] = LocaleRef(name)
    return r


_PRIM_NAMES = {"Z": "boolean", "B": "byte", "S": "short", "C": "char", "I": "int", "J": "long", "F": "float",
               "D": "double", "V": "void"}


def _java_name(desc):
    if desc in _PRIM_NAMES:
        return _PRIM_NAMES[desc]
    if desc.startswith("["):
        return desc.replace("/", ".")
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return None


def _desc_of(name):
    """Class.forName's argument (a BINARY name, `com.x.Maze`, `com.x.Outer$In`, or an array descriptor written with
    dots, `[Lcom.x.Maze;`, `[I`) as a type descriptor; None for a name ART refuses with ClassNotFoundException
    (IsValidBinaryClassName): a slash anywhere, a descriptor form `Lcom.x;` outside an array, an empty segment,
    surrounding whitespace."""
    if not isinstance(name, str) or not name or name != name.strip() or "/" in name:
        return None
    if name.startswith("["):
        d = name.replace(".", "/")
        el = d.lstrip("[")
        if (len(el) == 1 and el in "ZBSCIJFD") or (len(el) > 2 and el[0] == "L" and el[-1] == ";"
                                                   and ";" not in el[1:-1] and "[" not in el
                                                   and all(el[1:-1].split("/"))):
            return d
        return None
    if ";" in name or "[" in name or not all(name.split(".")):
        return None
    return "L" + name.replace(".", "/") + ";"


# Framework classes present on every Android runtime (Class.forName of one of them cannot throw). Anything else that
# no dex of the package defines may be absent on the device (a hook framework's class: the classic `try { forName(..)
# } catch (ClassNotFoundException e)` probe), and the VM, which never takes a catch path, declines.
_CORE_CLASSES = frozenset("L%s;" % c for c in (
    "java/lang/Object", "java/lang/String", "java/lang/CharSequence", "java/lang/Integer", "java/lang/Long",
    "java/lang/Short", "java/lang/Byte", "java/lang/Character", "java/lang/Boolean", "java/lang/Float",
    "java/lang/Double", "java/lang/Number", "java/lang/Void", "java/lang/Math", "java/lang/StrictMath",
    "java/lang/System", "java/lang/StringBuilder", "java/lang/StringBuffer", "java/lang/Class", "java/lang/Thread",
    "java/lang/Runtime", "java/lang/Enum", "java/lang/reflect/Method", "java/lang/reflect/Field",
    "java/util/Arrays", "java/util/ArrayList", "java/util/HashMap", "java/util/List", "java/util/Map",
    "java/util/Locale", "java/util/Random", "java/security/MessageDigest", "javax/crypto/Cipher",
    "android/os/Build", "android/util/Base64", "android/util/Log", "android/app/Activity"))


def _exists(vm, desc):
    """True only when the class certainly exists for the app's code on the device: a primitive, a class of the running
    dex itself, a class of the APK root's classes.dex, classes2.dex, ... (the app class loader's path; a class only an
    assets/*.dex or a nested dex defines is loaded by a loader the app builds, if at all: review of 5ffe7f3, R4), a
    core framework class, or an array of one of those."""
    if not isinstance(desc, str) or not desc:
        return False
    if len(desc) == 1:
        return desc in _PRIM_NAMES and desc != "V"
    if desc.startswith("["):
        el = desc.lstrip("[")
        return (len(el) == 1 and el in "ZBSCIJFD") or (len(el) > 1 and _exists(vm, el))
    if desc in _ci(vm.dex).cls:
        return True
    ext = _ext(vm)
    if ext is not None and desc in ext.get("loadable", ()):
        return True
    return desc in _CORE_CLASSES


def _package(desc):
    return desc[:desc.rfind("/") + 1] if desc.startswith("L") else None


def _caller_class(vm):
    """The class of the app method that is executing the current invoke (the innermost VM._exec frame on the Python
    stack, mapped to its method by the identity of its instruction list), or None when it cannot be told."""
    dex = vm.dex
    ids = getattr(dex, "_dfl_ins_ids", None)
    if ids is None:
        ids = dex._dfl_ins_ids = {id(v[2]): m for m, v in dex.code.items()}
    target = getattr(type(vm), "_exec", None)
    target = getattr(target, "__code__", None)
    try:
        f = sys._getframe(1)
    except Exception:
        return None
    while f is not None:
        if f.f_code is target:
            ins = f.f_locals.get("ins")
            m = ids.get(id(ins))
            if m is not None and dex.code[m][2] is ins:
                return dex.mname[m][0]
            return None
        f = f.f_back
    return None


def _member_access(vm, declaring, member_acc, accessible, what):
    """ART's VerifyAccess for a reflective Method.invoke / Field.get / Field.set without setAccessible(true): allowed
    from the declaring class itself; else the class must be public or in the caller's package, and the member public,
    or package-private / protected in the caller's package. Anything else (a private member of another class, a
    protected member through a subclass elsewhere, an unknown caller) declines: the device throws
    IllegalAccessException there, or the VM cannot tell."""
    if accessible:
        return
    ci = _ci(vm.dex)
    info = ci.cls.get(declaring)
    cacc = info.acc if info is not None else 0
    if (member_acc & ACC_PUBLIC) and (cacc & ACC_PUBLIC):
        return
    caller = _caller_class(vm)
    if caller is None:
        _decline(vm, "reflective access to a non-public %s: the calling class is not known" % what)
    if caller == declaring:
        return
    same_pkg = _package(caller) is not None and _package(caller) == _package(declaring)
    if not ((cacc & ACC_PUBLIC) or same_pkg):
        _decline(vm, "reflective access to %s of a class the caller cannot access" % what)
    if member_acc & ACC_PUBLIC:
        return
    if not (member_acc & ACC_PRIVATE) and same_pkg:
        return
    _decline(vm, "reflective access to a non-public %s without setAccessible(true) (IllegalAccessException)" % what)


def _proto(dex, midx):
    """(shorty, [param type descriptors] or None) of method_ids[midx], cached on the dex."""
    cache = getattr(dex, "_dfl_proto", None)
    if cache is None:
        cache = dex._dfl_proto = {}
    r = cache.get(midx)
    if r is None:
        r = cache[midx] = _proto_read(dex, midx)
    return r


def _proto_read(dex, midx):
    sh = dex.meth_shorty(midx)
    try:
        pidx = dex._u2(dex.meth_off + midx * 8 + 2)
        poff = dex._u4(dex.proto_off + pidx * 12 + 8)
        if not poff:
            return sh, ([] if sh is not None and len(sh) == 1 else None)
        n = dex._u4(poff)
        return sh, [dex.type_str(dex._u2(poff + 4 + 2 * i)) for i in range(n)]
    except Exception:
        return sh, None


def _params_match(dex, midx, want):
    sh, types = _proto(dex, midx)
    if sh is None:
        return None
    if len(sh) - 1 != len(want):
        return False
    for i, w in enumerate(want):
        p = sh[1 + i]
        if p == "L":
            if len(w) == 1:
                return False                         # a primitive class for a reference parameter
            if types is None:
                return None                          # the reference type is not known here
            if types[i] != w:
                return False
        elif w != p:
            return False
    return True


_WIDEN = {"B": "BSIJFD", "S": "SIJFD", "C": "CIJFD", "I": "IJFD", "J": "JFD", "F": "FD", "D": "D", "Z": "Z"}


def _widen(vm, t, v, to):
    """Java's unboxing + widening of a box of type t (value v as the VM holds it) to primitive `to` (JLS 5.1.2), as
    the register value; declines when Java would throw IllegalArgumentException."""
    if to not in _WIDEN.get(t, ""):
        _decline(vm, "argument of type %s cannot widen to %s" % (t, to))
    if t == to:
        if to in "JD":
            return v & M64
        if to == "F":
            return v & M32
        return v
    if t in "BSCI":
        iv = _s32(v) if t == "I" else (v & 0xFFFF if t == "C" else v)
        if to in "SI":
            return iv
        if to == "J":
            return iv & M64
        if to == "F":
            return f32_bits(float(iv))
        return f64_bits(float(iv))
    if t == "J":
        lv = _s64(v)
        return long_to_f32_bits(lv) if to == "F" else f64_bits(float(lv))
    if t == "F":
        return f64_bits(f32(v))
    _decline(vm, "widening")


def _box(vm, t, v):
    Box = _G(vm)["_Box"]
    if t == "Z":
        return Box("Z", bool(v))
    if t == "J":
        return Box("J", v & M64)
    if t == "I":
        return Box("I", _s32(v))
    if t == "B":
        return Box("B", _s8(v))
    if t == "S":
        return Box("S", _s16(v))
    if t == "C":
        return Box("C", v & 0xFFFF)
    if t == "F":
        return Box("F", v & M32)
    if t == "D":
        return Box("D", v & M64)
    _decline(vm, "box type")


def _legacy_frame(vm, arr):
    """The argument frame the VM built before this module (to tell which reflective calls changed)."""
    Box = _G(vm)["_Box"]
    frame = []
    for el in arr:
        if isinstance(el, Box):
            frame.append(el.v & M64 if el.t in ("J", "D") else el.v)
            if el.t in ("J", "D"):
                frame.append(0)
        elif isinstance(el, int) or el is None:
            frame.append(el)
        else:
            return None
    return frame


def _declared(dex, desc, name):
    """method_ids of every method class `desc` DECLARES under `name` (with a body or not: a native or abstract overload
    takes part in the resolution too), from the class index."""
    ci = _ci(dex)
    r = ci._decl.get((desc, name))
    if r is None:
        r = ci._decl[(desc, name)] = [mi for mi in ci.macc if dex.meth(mi) == (desc, name)]
    return r


_BOX_OF = {"Ljava/lang/Long;": "J", "Ljava/lang/Integer;": "I", "Ljava/lang/Short;": "S", "Ljava/lang/Byte;": "B",
           "Ljava/lang/Character;": "C", "Ljava/lang/Boolean;": "Z", "Ljava/lang/Float;": "F",
           "Ljava/lang/Double;": "D"}


def _ref_arg_ok(vm, ptype, el):
    """Method.invoke checks a reference argument against the parameter's type (IllegalArgumentException when it is
    not an instance). True only where the VM value certainly is one (or null)."""
    G = _G(vm)
    if el is None or el == 0 and isinstance(el, int) and not isinstance(el, bool):
        return True                                   # null fits any reference parameter
    if ptype is None:
        return False
    if ptype == "Ljava/lang/Object;":
        return True
    if ptype in ("Ljava/lang/String;", "Ljava/lang/CharSequence;"):
        return isinstance(el, (str, G["_Str"])) or (ptype.endswith("CharSequence;") and isinstance(el, G["_SB"]))
    if ptype in _BOX_OF:
        return isinstance(el, G["_Box"]) and el.t == _BOX_OF[ptype]
    if ptype.startswith("["):
        return isinstance(el, list)
    if isinstance(el, G["_Obj"]):
        ci = _ci(vm.dex)
        c, seen = el.type, set()
        while c is not None and c not in seen:
            if c == ptype:
                return True
            seen.add(c)
            info = ci.cls.get(c)
            c = info.sup if info is not None else None
    return False


def _resolve_method(vm, desc, name, params, public_only):
    """(the one method_id that Class.getDeclaredMethod (public_only False) or getMethod (True) of `name` with the
    parameter classes `params` finds in class `desc`, the number of methods of that name it declares). Declines where
    the device may throw NoSuchMethodException or the VM cannot tell: <init> / <clinit>, a parameter Class not known,
    no declared method of that name and parameters, or more than one (getMethod: a public one declared in the class
    itself; an inherited one is not searched), a class defined more than once. Asked at the lookup itself (review of
    5ffe7f3, R5: a lookup with no invoke after it went on, the hook probe `try { c.getDeclaredMethod("x"); decoy }
    catch (NoSuchMethodException e) { real }`) and again by Method.invoke."""
    dex = vm.dex
    if name.startswith("<"):
        _decline(vm, "getDeclaredMethod/getMethod of %s (Java throws NoSuchMethodException)" % name)
    if params is None:
        _decline(vm, "reflect parameter classes not all known (a null or unmodelled Class in the Class[])")
    ci = _ci(dex)
    ext = _ext(vm)
    if desc in ci.dup or (ext is not None and desc in ext.get("dup", ())):
        _decline(vm, "reflect method of %s, a class defined more than once (the device runs one copy)" % desc)
    cands = list(_declared(dex, desc, name))
    if not cands:                                    # a stand-in dex without class_data: the method bodies it has
        cands = [mi for mi, mn in dex.mname.items() if mn == (desc, name)]
    n_before = len(cands)                            # counted before getMethod's public filter (review of 4917e79)
    if public_only:
        cands = [mi for mi in cands if ci.macc.get(mi, 0) & ACC_PUBLIC]
    keep = []
    for mi in cands:
        ok = _params_match(dex, mi, params)
        if ok is None:
            _decline(vm, "reflect overload resolution needs the parameter types")
        if ok:
            keep.append(mi)
    if len(keep) != 1:
        _decline(vm, "reflect method %s->%s does not resolve uniquely (%d): NoSuchMethodException on the device, or "
                 "not known here" % (desc, name, len(keep)))
    return keep[0], n_before


def _method_invoke(vm, args):
    G = _G(vm)
    dex = vm.dex
    Box, Obj = G["_Box"], G["_Obj"]
    mt = args[0] if args else None
    if isinstance(mt, CrossMethodRef):
        return _cross_invoke(vm, mt, args)           # B-249: resolved in another dex member (CROSSDEX)
    if not isinstance(mt, MethodRef) or mt.desc is None or mt.name is None:
        _decline(vm, "reflect target unresolved")
    ci = _ci(dex)
    tgt, n_before = _resolve_method(vm, mt.desc, mt.name, mt.params, mt.public_only)
    narrowed = n_before > 1
    if tgt not in dex.code:
        _decline(vm, "reflect target %s->%s has no body here (native or abstract)" % (mt.desc, mt.name))
    # the body the VM before this module ran: the first method of that class and name with code, whatever its
    # parameters or access; another body is a call only this module resolves (review of 4917e79: getMethod's public
    # filter picked f(long) over a private f(int), and the code landed under the judged key)
    legacy_tgt = next((mi for mi, mn in dex.mname.items() if mn == (mt.desc, mt.name) and mi in dex.code), None)
    narrowed = narrowed or legacy_tgt != tgt
    arr = args[2] if len(args) > 2 else []
    if arr == 0 or arr is None:
        arr = []
    if not isinstance(arr, list):
        _decline(vm, "reflect args not an Object[]")
    sh = dex.meth_shorty(tgt)
    legacy = _legacy_frame(vm, arr)
    if sh is None:
        if legacy is None:
            _decline(vm, "reflect arg type")
        out = vm.run(tgt, legacy)                    # no proto in this dex: the VM's old behaviour exactly
        return _Box_long_legacy(vm, out)
    acc = ci.macc.get(tgt)
    # a direct method with no access flag at all exists only in a hand-built test dex: it is read as static, as the
    # VM always did (a real static carries ACC_STATIC, a private instance method ACC_PRIVATE, a constructor 0x10000)
    static = acc is None or bool(acc & ACC_STATIC) or (acc == 0 and tgt in ci.direct)
    if acc is not None:
        _member_access(vm, mt.desc, acc, mt.accessible, "method %s->%s" % (mt.desc, mt.name))
    if len(sh) - 1 != len(arr):
        _decline(vm, "reflect arity")
    _sh, ptypes = _proto(dex, tgt)
    frame = []
    new = narrowed
    if static:
        ensure_init(vm, mt.desc)                     # a reflective static call initializes the declaring class
    else:
        recv = args[1] if len(args) > 1 else None
        if not isinstance(recv, Obj):
            _decline(vm, "reflect instance method needs a receiver object")
        # the receiver must be an instance of the declaring class; a virtual method is dispatched on its class, so
        # an override between the two declines (the VM runs the declared body only)
        c, seen = recv.type, set()
        virtual = tgt not in ci.direct
        key = (mt.name, dex._u2(dex.meth_off + tgt * 8 + 2))
        while c != mt.desc:
            info = ci.cls.get(c)
            if info is None or c in seen or c in ci.dup:
                _decline(vm, "reflect receiver %s is not provably a %s" % (recv.type, mt.desc))
            seen.add(c)
            if virtual and key in info.vmeth:
                _decline(vm, "reflect virtual call: %s overrides %s->%s" % (c, mt.desc, mt.name))
            c = info.sup
            if c is None:
                _decline(vm, "reflect receiver %s is not a %s" % (recv.type, mt.desc))
        frame.append(recv)
        new = True
    for i, (p, el) in enumerate(zip(sh[1:], arr)):
        if p == "L":
            pt = ptypes[i] if ptypes is not None and i < len(ptypes) else None
            if not _ref_arg_ok(vm, pt, el):
                _decline(vm, "reflect argument %d does not certainly fit %s" % (i, pt))
            frame.append(el)
            if isinstance(el, Box):
                new = True                           # the box itself, not its value (before: the value)
        else:
            if not isinstance(el, Box):
                _decline(vm, "reflect primitive argument is not a box")
            frame.append(_widen(vm, el.t, el.v, p))
            if p in "JD":
                frame.append(0)
            if el.t != p:
                new = True
    if legacy is None or len(legacy) != len(frame) or any(
            (a is not b) and not (isinstance(a, int) and isinstance(b, int) and a == b)
            for a, b in zip(legacy, frame)):
        new = True
    out = vm.run(tgt, frame)
    r = sh[0]
    if r == "V":
        res = None
    elif r == "L":
        res = out
        if isinstance(out, int):
            new = True                               # a null reference; before, an int was boxed as a Long
    else:
        if not isinstance(out, int):
            _decline(vm, "reflect primitive return is not a number")
        res = _box(vm, r, out)
        if r != "J":
            new = True
    if new:
        _feat(vm, REFLECT)
    return res


def _Box_long_legacy(vm, out):
    if isinstance(out, int):
        return _G(vm)["_Box"]("J", out & M64)
    return out


def _field_access(vm, fr):
    _member_access(vm, fr.fkey[0], fr.acc, fr.accessible, "field %s->%s" % (fr.fkey[0], fr.fkey[1]))


def _field_get(vm, name, args):
    fr = args[0]
    if not fr.static:
        _decline(vm, "Field.%s on an instance field is not modelled" % name)
    _field_access(vm, fr)
    ftype = fr.fkey[2]
    ensure_init(vm, fr.fkey[0])
    v = _read_static(vm, _ci(vm.dex), fr.fkey)
    _static_feat(vm)
    _feat(vm, REFLECT)
    if name == "get":
        if ftype[:1] in "L[":
            return v
        return _box(vm, ftype, v)
    want = {"getInt": "I", "getLong": "J", "getFloat": "F", "getDouble": "D", "getBoolean": "Z", "getByte": "B",
            "getShort": "S", "getChar": "C"}.get(name)
    if want is None or ftype[:1] in "L[":
        _decline(vm, "Field.%s on %s" % (name, ftype))
    return _widen(vm, ftype, v, want)


def _field_set(vm, name, args):
    G = _G(vm)
    Box = G["_Box"]
    fr = args[0]
    if not fr.static:
        _decline(vm, "Field.%s on an instance field is not modelled" % name)
    if fr.acc & ACC_FINAL:
        _decline(vm, "Field.%s of a static final field (Java throws IllegalAccessException)" % name)
    _field_access(vm, fr)
    ftype = fr.fkey[2]
    if name == "set":
        if len(args) != 3:
            _decline(vm, "Field.set shape")
        val = args[2]
        if ftype[:1] in "L[":
            if ftype != "Ljava/lang/String;" or not isinstance(val, str):
                _decline(vm, "Field.set of a reference static other than a String")
            store = val
        else:
            if not isinstance(val, Box):
                _decline(vm, "Field.set of a primitive static needs a box")
            store = _widen(vm, val.t, val.v, ftype)
    else:
        src = {"setInt": "I", "setLong": "J", "setFloat": "F", "setDouble": "D", "setBoolean": "Z",
               "setByte": "B", "setShort": "S", "setChar": "C"}.get(name)
        if src is None or ftype[:1] in "L[" or len(args) < 3 or not isinstance(args[2], int):
            _decline(vm, "Field.%s shape" % name)
        store = _widen(vm, src, args[2], ftype)
    ensure_init(vm, fr.fkey[0])
    st = _st(vm)
    st.store[fr.fkey] = store
    st.dirty[fr.fkey] = None
    st.last[fr.fkey] = "run" if st.depth == 0 else "clinit"
    _feat(vm, REFLECT)
    return None


def _reflect(vm, op, cls, name, args, shorty):
    """(handled, result) for java.lang.Class / reflect.Method / reflect.Field / AccessibleObject / Object.getClass."""
    G = _G(vm)
    dex = vm.dex
    text = G["_as_text"]
    if cls == "Ljava/lang/Class;":
        if name == "forName":
            nm = text(args[0]) if args else None
            desc = _desc_of(nm)
            if desc is None:
                _decline(vm, "Class.forName(%r): not a binary name ART loads (ClassNotFoundException)" % (nm,))
            if len(args) == 3:
                # forName(name, initialize, loader) loads through `loader`, never the caller's: a null one is the
                # bootstrap loader (boot classes only), any other one an object the VM cannot prove (dexfloat-residuals:
                # the loader was ignored, and an app class resolved through the bootstrap loader, a path no device takes)
                _forname_loader(vm, args, desc, nm)
            if not _exists(vm, desc):
                # the device may throw ClassNotFoundException here (a hook framework probe), and the VM never takes
                # the catch path: only a class the package defines or a core framework class is certain to load
                _decline(vm, "Class.forName(%r): the class may be absent on the device" % (nm,))
            init = True
            if len(args) == 3:
                init = bool(args[1])
            elif len(args) != 1:
                _decline(vm, "Class.forName shape")
            if init and desc[:1] == "L":
                # a class of this dex runs its <clinit> here; a framework class needs nothing; a class of another dex
                # member runs a <clinit> the VM does not see, and the values the run stored before it go stale
                # (ensure_init, _unseen)
                ensure_init(vm, desc)
            return True, _cref(vm, desc)
        ct = args[0] if args else None
        if not isinstance(ct, ClassRef):
            _decline(vm, "Class.%s on an unresolved class" % name)
        if name in ("getDeclaredMethod", "getMethod"):
            nm = text(args[1]) if len(args) > 1 else None
            if nm is None:
                _decline(vm, "Class.%s name" % name)
            arr = args[2] if len(args) > 2 else []
            params = None
            if arr == 0 or arr is None:
                params = []
            elif isinstance(arr, list):
                params = [e.desc for e in arr] if all(isinstance(e, ClassRef) for e in arr) else None
            other = _cross_definer(vm, ct.desc)
            if other is not None:
                # B-249 (CROSSDEX): a pure primitive static of a class another classpath dex member defines
                ref = _cross_method_ref(vm, other, ct.desc, nm, params, name == "getMethod")
                if ref is not None:
                    _feat(vm, CROSSDEX)
                    return True, ref
            # the lookup itself throws NoSuchMethodException on the device when nothing matches (R5)
            _resolve_method(vm, ct.desc, nm, params, name == "getMethod")
            return True, MethodRef(ct.desc, nm, params, name == "getMethod")
        if name in ("getDeclaredField", "getField"):
            nm = text(args[1]) if len(args) > 1 else None
            ci = _ci(dex)
            info = ci.cls.get(ct.desc)
            if nm is None or info is None or ct.desc in ci.dup:
                _decline(vm, "Class.%s outside this dex" % name)
            hits = [(fk, a, True) for fk, a in info.sf if fk[1] == nm] + \
                   [(fk, a, False) for fk, a in info.inst if fk[1] == nm]
            if len(hits) != 1:
                _decline(vm, "Class.%s %s does not resolve uniquely in %s" % (name, nm, ct.desc))
            fk, a, static = hits[0]
            if name == "getField" and not (a & ACC_PUBLIC):
                _decline(vm, "Class.getField of a non-public field (inherited search not modelled)")
            _feat(vm, REFLECT)
            return True, FieldRef(fk, a, static)
        if name == "getName" and len(args) == 1:
            jn = _java_name(ct.desc)
            if jn is None or not _exists(vm, ct.desc):
                # a const-class of a type nothing here proves present throws NoClassDefFoundError on the device
                _decline(vm, "Class.getName of %s" % ct.desc)
            _feat(vm, REFLECT)
            return True, jn
        if name in ("getSimpleName", "getCanonicalName") and len(args) == 1:
            # `private static final String TAG = C.class.getSimpleName();` (review of 4917e79: the <clinit> stopped
            # there, and every invoke-static of C declined where the VM before this module answered). Exact for a
            # top-level class of this dex: no `$` in its name and no InnerClass / EnclosingClass / EnclosingMethod
            # annotation (a member, local or anonymous class, whose simple name is another), defined by one dex only
            ci = _ci(dex)
            info = ci.cls.get(ct.desc)
            ext = _ext(vm)
            if (info is None or info.annot or ct.desc in ci.dup or "$" in ct.desc or not ct.desc.startswith("L")
                    or (ext is not None and ct.desc in ext.get("dup", ()))):
                _decline(vm, "Class.%s of %s: not a top-level class of this dex (a nested one's name is another)"
                         % (name, ct.desc))
            bn = ct.desc[1:-1]
            _feat(vm, REFLECT)
            return True, bn.rsplit("/", 1)[-1] if name == "getSimpleName" else bn.replace("/", ".")
        return False, None
    if name == "setAccessible" and cls in ("Ljava/lang/reflect/AccessibleObject;", "Ljava/lang/reflect/Method;",
                                           "Ljava/lang/reflect/Field;"):
        tok = args[0] if args else None
        if len(args) != 2 or not isinstance(args[1], int):
            _decline(vm, "setAccessible shape")
        if isinstance(tok, (MethodRef, FieldRef)):
            tok.accessible = bool(args[1])
            if cls != "Ljava/lang/reflect/AccessibleObject;":
                _feat(vm, REFLECT)                    # the VM before this module declined Method/Field.setAccessible
            return True, None
        _decline(vm, "setAccessible on an unresolved token")
    if cls == "Ljava/lang/reflect/Method;" and name == "invoke":
        return True, _method_invoke(vm, args)
    if cls == "Ljava/lang/reflect/Field;":
        fr = args[0] if args else None
        if not isinstance(fr, FieldRef):
            _decline(vm, "Field.%s on an unresolved field" % name)
        if name == "getName" and len(args) == 1:
            _feat(vm, REFLECT)
            return True, fr.fkey[1]
        if name.startswith("get"):
            if len(args) != 2:
                _decline(vm, "Field.%s shape" % name)
            return True, _field_get(vm, name, args)
        if name.startswith("set"):
            return True, _field_set(vm, name, args)
        return False, None
    if cls == "Ljava/lang/Object;" and name == "getClass" and len(args) == 1:
        o = args[0]
        if isinstance(o, G["_Obj"]):
            desc = o.type
            _runtime_class_known(vm, desc)
        elif isinstance(o, (str, G["_Str"])):
            desc = "Ljava/lang/String;"
        else:
            _decline(vm, "getClass of an untyped value")
        _feat(vm, REFLECT)
        return True, _cref(vm, desc)
    return False, None


# ====================================================================== B-249: text, cross-DEX
# Two subsets the Day 30 coverage matrix left open (M5: "reflection/StringBuilder/cross-DEX subsets remain"), each a
# decline on the tree before (a None, never a wrong answer), each answered here only where Java's result is exact, and
# each under a capability family of its own, so a code that needed one is unsure under `analysis+dex-text` /
# `analysis+dex-crossdex` until the judge accepts that exact name (key_suffix):
#
#   TEXT      StringBuilder / StringBuffer deleteCharAt, delete, replace, indexOf, lastIndexOf, substring; String
#             hashCode, equals, isEmpty, startsWith, endsWith, contains, lastIndexOf, compareTo. Java's bounds rules
#             (an index Java rejects declines: the VM takes no catch path) and its clamps (delete's and replace's end,
#             indexOf's fromIndex) as AbstractStringBuilder and String state them. Only text of BMP characters: a
#             supplementary character is two UTF-16 units in Java and one here, so its index or hash declines.
#   CROSSDEX  an invoke-static, or a Class.forName / getDeclaredMethod|getMethod / Method.invoke, of a static method a
#             class of ANOTHER dex member defines, when that member is on the app class loader's path (classes.dex,
#             classes2.dex, ... in order: _ext "loadable"), exactly one dex of the delivery defines the class, and the
#             call is a pure function the VM can run there: the class and every class the body reaches extend Object
#             with no <clinit> and no static_values (initializing it does nothing), every method reached is static
#             with primitive parameters and a primitive return, and its body (and each callee's) has no field access,
#             no string or class constant, no object, no invoke but invoke-static of such a method of the same dex,
#             and only local primitive arrays. Then the body runs on a fresh VM over that dex (the steps count against
#             the caller's budget) and its families join the caller's. Anything else keeps the decline it had.
TEXT = "dex-text"
CROSSDEX = "dex-crossdex"
_SB_CLASSES = ("Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;")
_SB_TEXT_OPS = frozenset(("deleteCharAt", "delete", "replace", "indexOf", "lastIndexOf", "substring"))
_STR_TEXT_OPS = frozenset(("hashCode", "equals", "isEmpty", "startsWith", "endsWith", "contains", "lastIndexOf",
                           "compareTo"))
_PURE_DEPTH = 6                  # nested invoke-static levels the purity scan follows
_PURE_UNITS = 1 << 15            # code units the purity scan reads for one call


def _bmp(vm, s, what):
    if any(ord(c) > 0xFFFF for c in s):
        _decline(vm, "%s of text with a supplementary character (two UTF-16 units in Java)" % what)
    return s


def _jint(vm, v, what):
    if isinstance(v, bool) or not isinstance(v, int):
        _decline(vm, "%s: an argument that is not an int" % what)
    return _s32(v)


def _index_of(s, t, start):
    """Java's String.indexOf(String, fromIndex)."""
    start = max(0, start)
    if start >= len(s):
        return len(s) if not t else -1
    return s.find(t, start)


def _last_index_of(s, t, start):
    """Java's String.lastIndexOf(String, fromIndex)."""
    right = len(s) - len(t)
    if start < 0:
        return -1
    start = min(start, right)
    if start < 0:
        return -1
    if not t:
        return start
    return s.rfind(t, 0, start + len(t))


def _text_arg(vm, v, what, seq_ok=False):
    G = _G(vm)
    if isinstance(v, str) or isinstance(v, G["_Str"]) or (seq_ok and isinstance(v, G["_SB"])):
        return _bmp(vm, G["_as_text"](v), what)
    _decline(vm, "%s: an argument that is not known text (null throws NullPointerException)" % what)


def _text_extra(vm, midx, cls, name, args):
    """(handled, result) for the TEXT methods (see the block comment above); (False, None) for any other."""
    G = _G(vm)
    sh, ptypes = _proto(vm.dex, midx)
    if sh is None or ptypes is None or not args:
        return False, None
    what = "%s.%s" % (cls[1:-1].rsplit("/", 1)[-1], name)
    if cls in _SB_CLASSES:
        if name not in _SB_TEXT_OPS or not isinstance(args[0], G["_SB"]):
            return False, None
        sb = args[0]
        s = _bmp(vm, "".join(sb.parts), what)
        n = len(s)
        if name == "deleteCharAt" and ptypes == ["I"]:
            i = _jint(vm, args[1], what)
            if not 0 <= i < n:
                _decline(vm, "%s: index %d out of range for length %d (Java throws)" % (what, i, n))
            sb.parts = [s[:i] + s[i + 1:]]
            res = sb
        elif name == "delete" and ptypes == ["I", "I"]:
            a, b = _jint(vm, args[1], what), _jint(vm, args[2], what)
            b = min(b, n)
            if a < 0 or a > b:
                _decline(vm, "%s(%d, %d) on length %d (Java throws)" % (what, a, b, n))
            sb.parts = [s[:a] + s[b:]]
            res = sb
        elif name == "replace" and ptypes == ["I", "I", _STR]:
            a, b = _jint(vm, args[1], what), _jint(vm, args[2], what)
            t = _text_arg(vm, args[3], what)
            if a < 0 or a > n or a > b:
                _decline(vm, "%s(%d, %d) on length %d (Java throws)" % (what, a, b, n))
            b = min(b, n)
            sb.parts = [s[:a] + t + s[b:]]
            res = sb
        elif name in ("indexOf", "lastIndexOf") and ptypes in ([_STR], [_STR, "I"]):
            t = _text_arg(vm, args[1], what)
            if name == "indexOf":
                res = _index_of(s, t, _jint(vm, args[2], what) if len(ptypes) == 2 else 0)
            else:
                res = _last_index_of(s, t, _jint(vm, args[2], what) if len(ptypes) == 2 else n)
        elif name == "substring" and ptypes in (["I"], ["I", "I"]):
            a = _jint(vm, args[1], what)
            b = _jint(vm, args[2], what) if len(ptypes) == 2 else n
            if a < 0 or b > n or a > b:
                _decline(vm, "%s(%d, %d) on length %d (Java throws)" % (what, a, b, n))
            res = s[a:b]
        else:
            return False, None
        _feat(vm, TEXT)
        return True, res
    if cls == _STR and name in _STR_TEXT_OPS:
        if not (isinstance(args[0], str) or isinstance(args[0], G["_Str"])):
            return False, None
        s = _bmp(vm, G["_as_text"](args[0]), what)
        n = len(s)
        if name == "hashCode" and ptypes == []:
            h = 0
            for c in s:
                h = (31 * h + ord(c)) & M32
            res = _s32(h)
        elif name == "equals" and ptypes == ["Ljava/lang/Object;"]:
            o = args[1]
            if isinstance(o, str) or isinstance(o, G["_Str"]):
                res = int(G["_as_text"](o) == s)
            elif o is None or isinstance(o, (G["_SB"], G["_Box"], G["_Obj"])):
                res = 0                  # null, or an object that is no String: String.equals is false
            else:
                return False, None
        elif name == "isEmpty" and ptypes == []:
            res = int(n == 0)
        elif name == "startsWith" and ptypes in ([_STR], [_STR, "I"]):
            t = _text_arg(vm, args[1], what)
            off = _jint(vm, args[2], what) if len(ptypes) == 2 else 0
            res = int(0 <= off <= n - len(t) and s.startswith(t, off))
        elif name == "endsWith" and ptypes == [_STR]:
            res = int(s.endswith(_text_arg(vm, args[1], what)))
        elif name == "contains" and ptypes == ["Ljava/lang/CharSequence;"]:
            res = int(_text_arg(vm, args[1], what, seq_ok=True) in s)
        elif name == "compareTo" and ptypes == [_STR]:
            t = _text_arg(vm, args[1], what)
            res = next((ord(x) - ord(y) for x, y in zip(s, t) if x != y), len(s) - len(t))
        elif name == "lastIndexOf" and ptypes in (["I"], ["I", "I"], [_STR], [_STR, "I"]):
            if ptypes[0] == "I":
                ch = _jint(vm, args[1], what)
                if not 0 <= ch <= 0xFFFF:
                    _decline(vm, "%s of a supplementary code point" % what)
                start = _jint(vm, args[2], what) if len(ptypes) == 2 else n - 1
                start = min(start, n - 1)
                res = -1 if start < 0 else s.rfind(chr(ch), 0, start + 1)
            else:
                t = _text_arg(vm, args[1], what)
                res = _last_index_of(s, t, _jint(vm, args[2], what) if len(ptypes) == 2 else n)
        else:
            return False, None
        _feat(vm, TEXT)
        return True, res
    return False, None


class CrossMethodRef(MethodRef):
    """A java.lang.reflect.Method of a static method of another dex member (CROSSDEX): the dex and its method id."""
    __slots__ = ("dex", "tgt")

    def __init__(self, desc, name, params, public_only, dex, tgt):
        super().__init__(desc, name, params, public_only)
        self.dex = dex
        self.tgt = tgt


_PRIM = "ZBSCIJFD"
# opcodes a pure primitive body may hold (see the block comment): moves, primitive move-result, returns of a value,
# numeric constants, arrays of primitives, branches, switches, comparisons, arithmetic and conversions, invoke-static
_PURE_OPS = frozenset([0x00] + list(range(0x01, 0x0c)) + [0x0f, 0x10] + list(range(0x12, 0x1a)) + [0x21, 0x23, 0x26]
                      + list(range(0x28, 0x3e)) + [0x44, 0x45, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4e, 0x4f, 0x50,
                                                    0x51, 0x71, 0x77] + list(range(0x7b, 0xe3)))


def _prim_shorty(sh):
    return isinstance(sh, str) and len(sh) >= 1 and sh[0] in _PRIM and all(c in _PRIM for c in sh[1:])


def _cross_class_ok(other, desc):
    """True when initializing `desc` of `other` does nothing: it extends Object, has no <clinit>, no static_values,
    lists no interface and is defined once in that dex."""
    ci = _ci(other)
    info = ci.cls.get(desc)
    return (info is not None and desc not in ci.dup and info.sup == "Ljava/lang/Object;" and info.clinit is None
            and not info.sv_off and not info.ifaces and not _boot_shadow(desc))


def _pure_body(vm, other, midx, depth, seen, budget):
    """True when method `midx` of `other` is a pure primitive static (see the block comment), with every invoke-static
    it holds one too; `budget` is a one-item list of the code units still to read."""
    if midx in seen:
        return True
    seen.add(midx)
    if depth > _PURE_DEPTH or midx not in other.code:
        return False
    desc = other.mname[midx][0]
    ci = _ci(other)
    if not _cross_class_ok(other, desc) or not (ci.macc.get(midx, 0) & ACC_STATIC) or ci.macc.get(midx, 0) & ACC_NATIVE:
        return False
    if not _prim_shorty(other.meth_shorty(midx)):
        return False
    W = _G(vm)["_W"]
    ins = other.code[midx][2]
    budget[0] -= len(ins)
    if budget[0] < 0:
        return False
    pc = 0
    try:
        while pc < len(ins):
            u = ins[pc]
            op = u & 0xFF
            if op == 0 and u >> 8 in (1, 2, 3):      # a switch or fill-array-data payload: data, not code
                if u == 0x0100:
                    pc += 4 + 2 * ins[pc + 1]
                elif u == 0x0200:
                    pc += 2 + 4 * ins[pc + 1]
                else:
                    width = ins[pc + 1]
                    count = ins[pc + 2] | (ins[pc + 3] << 16)
                    pc += 4 + (width * count + 1) // 2
                continue
            if op not in _PURE_OPS:
                return False
            if op == 0x23:                           # new-array: one-dimensional, of a primitive
                t = other.type_str(ins[pc + 1])
                if len(t) != 2 or t[0] != "[" or t[1] not in _PRIM:
                    return False
            if op in (0x71, 0x77):
                if not _pure_body(vm, other, ins[pc + 1], depth + 1, seen, budget):
                    return False
            pc += W[op]
    except (IndexError, struct.error, ValueError):
        return False
    return True


def _cross_definer(vm, desc):
    """The one OTHER dex of the delivery that defines `desc` when that dex is on the app class loader's path; None
    when this dex defines it, the package holds no such member, or more than one dex defines it."""
    ext = _ext(vm)
    if ext is None or not ext.get("multi") or desc not in (ext.get("loadable") or ()):
        return None
    if desc in _ci(vm.dex).cls or desc in _ci(vm.dex).dup:
        return None
    parsed = ext.setdefault("_parsed", {})        # this call's own parse of each member, kept with its ext
    mine = getattr(vm.dex, "d", None)
    hits, seen = [], set()
    for data in ext.get("datas") or ():
        data = bytes(data)
        if data == mine or data in seen:
            continue                              # this dex, or an identical copy of a member
        seen.add(data)
        d = parsed.get(data)
        if d is None:
            try:
                d = parsed[data] = _G(vm)["Dex"](data)
            except Exception:
                return None                       # a member that does not parse: what it defines is not known
        if desc in _ci(d).cls or desc in _ci(d).dup:
            hits.append(d)
    return hits[0] if len(hits) == 1 else None


def _cross_run(vm, other, tgt, frame):
    """Run `tgt` of `other` on a fresh VM, its steps against the caller's budget, its families joined to the caller's."""
    G = _G(vm)
    sub = type(vm)(other, G["_NativeTable"](), {})
    sub.max_steps = max(0, vm.max_steps - vm.steps)
    try:
        out = sub.run(tgt, frame)
    finally:
        vm.steps += sub.steps
        for fam in _vs(sub).feat or ():
            _feat(vm, fam)
    if vm.steps > vm.max_steps:
        _decline(vm, "step budget")
    _feat(vm, CROSSDEX)
    return out


def _cross_target(vm, other, desc, name, sh):
    """The one method of `desc` in `other` named `name` with shorty `sh` that is a pure primitive static, else None."""
    cands = [m for m in other.code if other.mname.get(m) == (desc, name) and other.meth_shorty(m) == sh]
    if len(cands) != 1:
        return None
    return cands[0] if _pure_body(vm, other, cands[0], 0, set(), [_PURE_UNITS]) else None


def _cross_static(vm, op, midx, cls, name, args):
    """(handled, result) for an invoke-static of a method of another dex member (CROSSDEX); (False, None) leaves the
    call to the decline it had."""
    if op not in INVOKE_STATIC or name.startswith("<"):
        return False, None
    sh = vm.dex.meth_shorty(midx)
    if not _prim_shorty(sh):
        return False, None
    other = _cross_definer(vm, cls)
    if other is None:
        return False, None
    tgt = _cross_target(vm, other, cls, name, sh)
    if tgt is None:
        return False, None
    return True, _cross_run(vm, other, tgt, list(args))


def _cross_method_ref(vm, other, desc, name, params, public_only):
    """Class.getDeclaredMethod / getMethod resolved in another dex member (CROSSDEX), or None (the usual resolution
    and its decline stand)."""
    if params is None or not all(isinstance(p, str) and len(p) == 1 and p in _PRIM for p in params):
        return None
    ci = _ci(other)
    cands = [m for m in _declared(other, desc, name)]
    keep = [m for m in cands if _params_match(other, m, params)]
    if len(keep) != 1 or keep[0] not in other.code:
        return None
    tgt = keep[0]
    if public_only and not ci.macc.get(tgt, 0) & ACC_PUBLIC:
        return None
    if not _pure_body(vm, other, tgt, 0, set(), [_PURE_UNITS]):
        return None
    return CrossMethodRef(desc, name, list(params), public_only, other, tgt)


def _cross_invoke(vm, mt, args):
    """Method.invoke of a CrossMethodRef: ART's access check (a public method of a public class, or setAccessible),
    the boxed arguments unboxed and widened as Java does, the result boxed."""
    other, tgt = mt.dex, mt.tgt
    ci = _ci(other)
    if not mt.accessible and not (ci.macc.get(tgt, 0) & ACC_PUBLIC and ci.cls[mt.desc].acc & ACC_PUBLIC):
        _decline(vm, "reflective access to a non-public %s->%s of another dex without setAccessible(true)"
                 % (mt.desc, mt.name))
    Box = _G(vm)["_Box"]
    arr = args[2] if len(args) > 2 else []
    if arr == 0 or arr is None:
        arr = []
    sh = other.meth_shorty(tgt)
    if not isinstance(arr, list) or len(arr) != len(sh) - 1:
        _decline(vm, "reflect arity")
    frame = []
    for p, el in zip(sh[1:], arr):
        if not isinstance(el, Box):
            _decline(vm, "reflect primitive argument is not a box")
        frame.append(_widen(vm, el.t, el.v, p))
        if p in "JD":
            frame.append(0)
    out = _cross_run(vm, other, tgt, frame)
    if not isinstance(out, int):
        _decline(vm, "reflect primitive return is not a number")
    _feat(vm, REFLECT)
    return _box(vm, sh[0], out)


# ====================================================================== the VM hooks
_REFLECT_CLASSES = ("Ljava/lang/Class;", "Ljava/lang/reflect/Method;", "Ljava/lang/reflect/Field;",
                    "Ljava/lang/reflect/AccessibleObject;", "Ljava/lang/Object;")
_GUARDED = ("Ljava/math/BigInteger;", "Ljava/util/concurrent/atomic/AtomicInteger;",
            "Ljava/util/concurrent/atomic/AtomicLong;", "Ljava/util/concurrent/atomic/AtomicBoolean;")
# The packages of a device's boot class path (java.*, android.*, ...): a class here that no dex of the delivery defines is
# the framework's, which the VM models (_framework). Lkotlin/ was here until the dexfloat-residuals fix: Kotlin's standard
# library is never on a device's boot class path, every app ships it in its own dexes (_APP_LIBS).
_FRAMEWORK = ("Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Lsun/", "Llibcore/", "Lorg/json/")
# Libraries every app ships itself, never on a boot class path: a class here is always the app's (run where this dex has
# its body, else declined, as any app class), never one the VM models as the framework's.
_APP_LIBS = ("Lkotlin/", "Lkotlinx/", "Landroidx/", "Landroid/support/")
# What the tree before that fix treated as framework: base_sget keeps it for the split reading (a restriction only).
_FRAMEWORK_KB7 = _FRAMEWORK + ("Lkotlin/",)
# Every package a device's boot class path holds (dex_chain_codec._BOOT_PREFIXES and the rest the review of the fix
# named): a class here that a dex of the delivery defines may be the boot copy on a device (_boot_shadow). Only for that
# check: a class of the packages past _FRAMEWORK that no dex defines stays an app class here, as on the tree before.
_BOOT_PKGS = _FRAMEWORK + ("Lorg/w3c/", "Lorg/xml/", "Lorg/xmlpull/", "Lorg/kxml2/", "Lorg/apache/http/",
                           "Lcom/android/internal/", "Lcom/android/org/", "Lcom/android/okhttp/", "Ljunit/")
_LOADER = "Ljava/lang/ClassLoader;"
# dex_chain_codec.VM models these classes by the END of their names (new-instance makes a StringBuilder or a String of
# any class whose name ends so; _invoke answers Integer/Long/Character/Boolean/StringBuilder/String calls of any class
# ending so): only the java.lang class itself is what the model computes (the adversarial pass of the dexfloat-residuals
# fix: java.lang.MyInteger.valueOf, a class no device has, was answered as Integer.valueOf, a WRONG plain).
_SUFFIX_MODELS = ("StringBuilder;", "StringBuffer;", "/String;", "Integer;", "Long;", "Character;", "Boolean;")
_SUFFIX_EXACT = frozenset(("Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;", "Ljava/lang/String;",
                           "Ljava/lang/Integer;", "Ljava/lang/Long;", "Ljava/lang/Character;", "Ljava/lang/Boolean;"))


def _suffix_guard(vm, desc, what):
    """Declines a class the base VM would model by the end of its name that is not the java.lang class itself."""
    if desc.endswith(_SUFFIX_MODELS) and desc not in _SUFFIX_EXACT:
        _decline(vm, "%s of %s: the VM's model of a java.lang class matches it by the end of its name only" % (what, desc))


# Framework classes whose constructor the base VM models by storing what framework code later reads (Cipher.init and
# Mac.init read the key's bytes, Cipher.init the IV), where a device's framework asks the object itself through methods
# an app subclass may override (getEncoded, getAlgorithm, getIV): the third adversarial pass of the dexfloat-residuals
# fix, `MyKey extends SecretKeySpec` overriding getEncoded() gave the code of the constructor's key bytes, a WRONG plain.
# And Random(long), whose constructor calls setSeed(long), which a subclass may override (the review of the fix).
_SPEC_MODELS = frozenset(("Ljavax/crypto/spec/SecretKeySpec;", "Ljavax/crypto/spec/IvParameterSpec;",
                          "Ljava/util/Random;"))


def _spec_guard(vm, cls, name, args):
    """Declines the modelled constructor of a _SPEC_MODELS class run on an object of another class (an app subclass)."""
    if name == "<init>" and cls in _SPEC_MODELS and args:
        o = args[0]
        if isinstance(o, _G(vm)["_Obj"]) and o.type != cls:
            _decline(vm, "%s.<init> on a %s: a device's framework reads it through methods an app subclass may "
                     "override (getEncoded, getIV), which the VM's model does not ask" % (cls, o.type))


# ---------------------------------------------------------------------- framework classes and the delivery's own
def _defined(vm):
    """Every class a dex of the delivery defines (a frozenset): the running dex's own (its class index, a class it
    defines twice too; a hand-built dex with no class_defs: the classes of its method bodies), the other dex members
    package_info summarized (_ext "defined": analysis_codes_ex), and the classes of the delivery's other parsed dexes
    the VM can reach (read through dex_chain_codec._dex_classes): those its native table carries as `dexes` (a table
    with symbols; VM.__init__ replaces an empty one) and, in the split reading, every dex of the bundle (SplitVM's
    `world.dexes`, (split, Dex) pairs). Kept on the running Dex for its call (attach() clears it): a function of the
    delivery, never of the bytes alone, so it is never kept in the bytes-keyed caches."""
    dex = vm.dex
    got = getattr(dex, "_dfl_defs", None)
    if got is not None:
        return got
    ci = _ci(dex)
    out = set(ci.cls)
    out |= ci.dup
    if not out:
        out = _body_classes(dex)
    ext = _ext(vm)
    if ext is not None:
        out |= ext.get("defined", set())
    more = list(getattr(getattr(vm, "native_syms", None), "dexes", None) or ())
    world = getattr(vm, "world", None)
    for item in (getattr(world, "dexes", None) or ()) if world is not None else ():
        more.append(item[1] if isinstance(item, tuple) and len(item) == 2 else item)
    for d in more:
        if d is dex:
            continue
        try:
            # read as the class index reads the running dex (a class_def whose class_idx does not name its own
            # methods' class, as hand-built fixtures write it, is the class its methods name)
            cd = _ci(d)
            t = set(cd.cls) | cd.dup
        except Exception:
            t = set()
        out.update(t if t else _body_classes(d))
    got = frozenset(out)
    try:
        dex._dfl_defs = got
    except Exception:
        pass
    return got


def _body_classes(dex):
    """The classes of a dex's method bodies (a hand-built stand-in with no class_defs: its `mname` may also name methods
    it only references, which define nothing)."""
    code = getattr(dex, "code", None) or {}
    mname = getattr(dex, "mname", None) or {}
    return {mname[m][0] for m in code if m in mname}


def _framework(vm, desc):
    """True when `desc` is a class the VM models as the device's framework: under a boot class path package
    (_FRAMEWORK), not under a library every app ships itself (_APP_LIBS), and defined by NO dex of the delivery. A class
    some dex of the delivery defines is never the framework's here (the residual of the KB-7 review: a constructor of a
    Lkotlin/ class of another dex read as a no-op, its methods took the framework's models): it is the app's class, run
    where this dex has its body and declined elsewhere, and under a boot package it declines at every use
    (_boot_shadow)."""
    if not desc.startswith(_FRAMEWORK) or desc.startswith(_APP_LIBS):
        return False
    return desc not in _defined(vm)


def _boot_shadow(desc):
    """True for a class under a boot class path package (_FRAMEWORK, not _APP_LIBS). Asked only of a class a dex of the
    delivery defines: a device's class loaders ask the boot class path first (parent-first delegation), so a device runs
    the boot copy where its boot class path holds the class and the app's copy only where it does not. Which one is not
    known here, so a body, a <clinit>, a static or an entry of such a class declines (it neither runs as the app's nor
    takes the framework's model). Every boot package counts (_BOOT_PKGS: org.xml, org.w3c, org.xmlpull too; the review
    of the fix ran a delivery's own org.xml.sax.helpers.AttributesImpl.getLength())."""
    return desc.startswith(_BOOT_PKGS) and not desc.startswith(_APP_LIBS)


def _shadows(vm):
    """The classes of a boot class path package that a dex of the delivery defines (sorted; usually none). Where there
    is one, a device may run the boot copy's code where the dex has a body (a library method another method of the dex
    calls), which the whole-dex scan cannot read: every static read the scan would decide declines (_history_free,
    _check_contents)."""
    dex = vm.dex
    got = getattr(dex, "_dfl_shadow", None)
    defs = _defined(vm)
    if got is None or got[0] is not defs:
        got = (defs, sorted(c for c in defs if _boot_shadow(c)))
        try:
            dex._dfl_shadow = got
        except Exception:
            pass
    return got[1]


def _no_shadow(vm, desc, what):
    if _boot_shadow(desc):
        _decline(vm, "%s of %s: a dex of the delivery defines this class of the boot class path's package, and a device "
                 "runs the boot copy where its boot class path holds it (parent-first): which copy runs is not known"
                 % (what, desc))


def _boot_loadable(vm, desc):
    """True only when the bootstrap class loader (a null ClassLoader) certainly loads `desc`: a core framework class
    (_CORE_CLASSES) no dex of the delivery defines, or an array of a primitive or of such a class. The bootstrap loader
    reads the boot class path alone: an app class (one of this dex, of classes2.dex, ...) is ClassNotFoundException."""
    if not isinstance(desc, str) or not desc:
        return False
    if desc.startswith("["):
        el = desc.lstrip("[")
        return (len(el) == 1 and el in "ZBSCIJFD") or (len(el) > 1 and _boot_loadable(vm, el))
    return desc in _CORE_CLASSES and _framework(vm, desc)


def _forname_loader(vm, args, desc, nm):
    """Class.forName(name, initialize, loader) (3 arguments): the class is loaded by `loader`, never by the caller's.
    A null loader is the bootstrap loader, which loads only boot classes (ClassNotFoundException for an app class: the
    VM, which takes no catch path, followed a path a device never takes); any other loader is an object whose
    loadClass the VM cannot prove (an app ClassLoader subclass decides, a loader the app built may not see the class).
    Declines unless the loader is null and the class is certain on the boot class path (_boot_loadable)."""
    loader = args[2] if len(args) > 2 else None
    if not _is_null(loader):
        _decline(vm, "Class.forName(%r, _, loader) with a class loader the VM cannot prove (%s)" % (
            nm, type(loader).__name__))
    if desc is None or not _boot_loadable(vm, desc):
        _decline(vm, "Class.forName(%r, _, null): the bootstrap loader loads only the boot class path's classes "
                 "(ClassNotFoundException on a device)" % (nm,))


def iget_unset(vm, obj, fid):
    """dex_chain_codec.VM._exec, an iget of instance field `fid` (this dex's field_ids) that this run never wrote on
    `obj`: Java's default (0, or null) only where the field resolves to a field a class of THIS dex declares (the run
    ran every constructor of this dex's classes on an object it created, and nothing it does not see can have written
    it). A field the reference does not resolve to here (a framework class's, set by a constructor or method the VM
    does not run: the base VM's <init> catch-all made `new android.graphics.Point(42, 43)` a no-op and `.x` read 0, a
    WRONG plain under the judged key in the adversarial pass of the dexfloat-residuals fix; or a field named through a
    class of another dex) declines. The split reading alike: its modelled framework objects already decline an
    int-indexed read (split_bundle._ModelFields, _AppInfoFields), and a field another dex's code wrote is kept under
    that dex's own field index."""
    ci = _ci(vm.dex)
    _no_alias(vm, ci, obj, fid)
    if not ci.cls or ci.resolve(fid, static=False) is not None:
        return 0                     # (a hand-built stand-in dex with no class_defs reads its defaults as before)
    t = ci.fid(fid)
    # the reference's class chain inside this dex (resolve() gives up at a class with interfaces): the field declared
    # by a class of this dex keeps Java's default; a chain that leaves the dex (a framework superclass, a class of
    # another dex), a class defined twice, a loop, or a chain that ends with no class declaring the field
    # (NoSuchFieldError on a device: the review of the fix) declines
    c, seen = (t[0] if t else None), set()
    while t is not None:
        if c is None or c == "Ljava/lang/Object;":
            break
        info = ci.cls.get(c)
        if info is None or c in ci.dup or c in seen:
            break
        if any(fk[1] == t[2] and fk[2] == t[1] for fk, _a in info.inst):
            return 0
        seen.add(c)
        c = info.sup
    _decline(vm, "instance field %s: this run never wrote it, and it is no field of a class this dex defines (a "
             "constructor or method the VM does not run sets it on a device)" % ("%s->%s" % (t[0], t[2]) if t else fid))


ALIAS_FIELDS = 512
"""Fields of one object the field-reference look (_no_alias) reads at an iget; an object holding more declines the read
(every Mobile delivery of Days 1-26: objects of a handful of fields)."""


def _no_alias(vm, ci, obj, fid):
    """Declines when `obj` holds the field of reference `fid` under ANOTHER field reference of this dex. The VM keys an
    object's fields by field reference, a device by the field resolved: Base.<init> writing n through Base's reference
    and the chain reading it through Sub's (javac names the qualifying type: `this.n` inside Base, `sub.n` outside) read
    0 where a device read 42, and a later write through Sub's reference left a read through Base's the earlier value
    (the second adversarial pass of the dexfloat-residuals fix; the VM before it alike). Two references are one field
    when both resolve here to the same field, or, where either does not resolve, when they name the same field name and
    type."""
    fields = obj.fields
    if len(fields) < 1 or (len(fields) == 1 and fid in fields):
        return
    if len(fields) > ALIAS_FIELDS:
        _decline(vm, "an object holding %d fields: past the %d the field-reference look reads" % (len(fields),
                                                                                                ALIAS_FIELDS))
    _charge(vm, len(fields))         # the look is counted against the step budget
    me = ci.resolve(fid, static=False)
    mt = ci.fid(fid) if me is None else None
    for k in list(fields):
        if k == fid or type(k) is not int:
            continue
        other = ci.resolve(k, static=False)
        if me is not None and other is not None:
            same = other == me
        else:
            ot = ci.fid(k)
            a_ = mt if me is None else (me[0], me[2], me[1])
            same = ot is not None and a_ is not None and ot[1] == a_[1] and ot[2] == a_[2]
        if same:
            _decline(vm, "instance field %s is held under two field references of this dex (the VM keys an object's "
                     "fields by reference, a device by the field: which write is current is not known)" % (
                         "%s->%s" % (me[0], me[1]) if me is not None else fid))


def iget_alias(vm, obj, fid):
    """dex_chain_codec.VM._exec, an iget of a field this run wrote, on an object holding more than one field: declines
    when the same field is held under another field reference too (_no_alias)."""
    _no_alias(vm, _ci(vm.dex), obj, fid)


def split_body(vm, midx, args=None):
    """split_bundle.SplitVM.run, before any body runs in the split reading (an ANS entry, a call, tier C's body in
    another split, a reflected method): a body of a class under a boot class path package that the bundle's dex
    defines declines (_boot_shadow: a device may run the boot copy; before, a bundle whose base dex defined
    java.lang.Integer.bitCount ran that body, a WRONG plain under the judged split-asset key), and so does a call (a
    frame is running: not an entry, whose frame of None stands for an unknown receiver) of an instance method on a null
    receiver (the review of the fix: `((H) null).key()` ran H.key, where a device throws NullPointerException). The full
    VM asks the same in pre_invoke and pre_entry."""
    mn = vm.dex.mname.get(midx)
    if mn is not None and mn[0].startswith(_BOOT_PKGS):
        _no_shadow(vm, mn[0], "%s->%s" % mn)
    if args and _null_ref(args[0]):
        world = getattr(vm, "world", None)
        if world is not None and getattr(world, "cur", None):
            acc = _ci(vm.dex).macc.get(midx)
            if acc is None or not acc & ACC_STATIC:
                _decline(vm, "%s->%s on a null receiver (NullPointerException on a device)" % (mn or (midx, "")))


def split_reflect_access(vm, dx, mi):
    """split_bundle.SplitVM._reflect, before a reflected method of dex `dx` runs: ART's access check of Method.invoke
    (the split reading does not track setAccessible): allowed from the declaring class itself, for a member that is
    public in a public class, or for one not private in the calling class's package; anything else declines
    (IllegalAccessException on a device: the review of the dexfloat-residuals fix ran a private method from another
    class, a WRONG plain under the judged split-asset key)."""
    decl = dx.mname.get(mi, (None,))[0] if hasattr(dx, "mname") else None
    ci = _ci(dx)
    flags = ci.macc.get(mi)
    caller = _caller_class(vm)
    if decl is None or flags is None or caller is None:
        _decline(vm, "reflect %s: its access is not known here" % (decl,))
    if caller == decl:
        return
    if flags & ACC_PRIVATE:
        _decline(vm, "reflect %s->%s: a private method from %s (IllegalAccessException on a device)"
                 % (decl, dx.mname[mi][1], caller))
    info = ci.cls.get(decl)
    same_pkg = _package(caller) == _package(decl)
    if same_pkg or (flags & ACC_PUBLIC and info is not None and info.acc & ACC_PUBLIC):
        return
    _decline(vm, "reflect %s->%s from %s: not accessible there (IllegalAccessException on a device)"
             % (decl, dx.mname[mi][1], caller))


_SERIAL, _COMPARABLE, _OBJECT = "Ljava/io/Serializable;", "Ljava/lang/Comparable;", "Ljava/lang/Object;"
_CAST_STR = frozenset(("Ljava/lang/String;", "Ljava/lang/CharSequence;", _COMPARABLE, _SERIAL))
_CAST_SB = frozenset(("Ljava/lang/CharSequence;", "Ljava/lang/Appendable;", _SERIAL))
_CAST_ARRAY = frozenset(("Ljava/lang/Cloneable;", _SERIAL))
_CAST_CLASS = frozenset(("Ljava/lang/Class;", "Ljava/lang/reflect/Type;", "Ljava/lang/reflect/GenericDeclaration;",
                         "Ljava/lang/reflect/AnnotatedElement;", _SERIAL))
_CAST_METHOD = frozenset(("Ljava/lang/reflect/Method;", "Ljava/lang/reflect/Executable;",
                          "Ljava/lang/reflect/AccessibleObject;", "Ljava/lang/reflect/Member;",
                          "Ljava/lang/reflect/AnnotatedElement;", "Ljava/lang/reflect/GenericDeclaration;"))
_CAST_FIELD = frozenset(("Ljava/lang/reflect/Field;", "Ljava/lang/reflect/AccessibleObject;",
                         "Ljava/lang/reflect/Member;", "Ljava/lang/reflect/AnnotatedElement;"))
_CAST_LOCALE = frozenset(("Ljava/util/Locale;", _SERIAL, "Ljava/lang/Cloneable;"))
_CAST_CHARSET = frozenset(("Ljava/nio/charset/Charset;", _COMPARABLE))
_BOX_CLASS = {"Z": "Ljava/lang/Boolean;", "B": "Ljava/lang/Byte;", "S": "Ljava/lang/Short;", "C": "Ljava/lang/Character;",
              "I": "Ljava/lang/Integer;", "J": "Ljava/lang/Long;", "F": "Ljava/lang/Float;", "D": "Ljava/lang/Double;"}


def _obj_is(vm, t, desc):
    """True when an object of class `t` is certainly an instance of `desc`: `desc` is `t`, or a superclass or interface
    the class chain names inside this dex (past a class this dex does not define nothing more is known)."""
    ci = _ci(vm.dex)
    todo, seen = [t], set()
    while todo:
        c = todo.pop()
        if c in seen:
            continue
        seen.add(c)
        if c == desc:
            return True
        info = ci.cls.get(c)
        if info is None or c in ci.dup:
            continue
        if info.sup:
            todo.append(info.sup)
        todo.extend(info.ifs or ())
        if len(seen) > 256:
            return False
    return False


def check_cast(vm, v, tidx):
    """dex_chain_codec.VM._exec, check-cast vAA, type@BBBB: a device throws ClassCastException when the reference is not
    null and not an instance of the type, where the VM went on (the review of the dexfloat-residuals fix: an object of
    Y cast to an unrelated X, then X.n read 0, a WRONG plain under the judged key, the same on the tree before). Passes
    a null (and an entry's unknown argument, as before), and a value the VM certainly holds an instance of: a String,
    a box to its class, Number, Comparable or Serializable, an array to an array type, an object to a class or
    interface its chain names inside this dex, a reflection token, Locale or Charset to its own types. Anything else
    declines (an array's element type is not held by the VM: an array to any array type passes)."""
    if v is None or (type(v) is int and v == 0):
        return
    try:
        desc = vm.dex.type_str(tidx)
    except Exception:
        _decline(vm, "check-cast: the type is not in the dex")
    if desc == _OBJECT:
        return
    G = _G(vm)
    if isinstance(v, (str, G["_Str"])):
        ok = desc in _CAST_STR
    elif isinstance(v, G["_SB"]):
        ok = desc in _CAST_SB
    elif isinstance(v, G["_Box"]):
        ok = (desc == _BOX_CLASS.get(v.t) or desc in (_COMPARABLE, _SERIAL)
              or (desc == "Ljava/lang/Number;" and v.t in "BSIJFD"))
    elif isinstance(v, list):
        ok = desc.startswith("[") or desc in _CAST_ARRAY
    elif isinstance(v, G["_Obj"]):
        ok = _obj_is(vm, v.type, desc)
    elif isinstance(v, ClassRef) or type(v).__name__ == "_ClassTok":
        ok = desc in _CAST_CLASS
    elif isinstance(v, MethodRef) or type(v).__name__ == "_MethTok":
        ok = desc in _CAST_METHOD
    elif isinstance(v, FieldRef):
        ok = desc in _CAST_FIELD
    elif isinstance(v, LocaleRef):
        ok = desc in _CAST_LOCALE
    elif type(v).__name__ == "_Charset":
        ok = desc in _CAST_CHARSET
    elif isinstance(v, ContextRef):
        ok = desc == _CONTEXT
    else:
        ok = False
    if not ok:
        _decline(vm, "check-cast of a %s to %s: not certainly an instance (ClassCastException on a device)"
                 % (getattr(v, "type", type(v).__name__), desc))


def _runtime_class_known(vm, desc):
    """Object.getClass of a VM object of class `desc`: known only for a class a dex of the delivery defines (the object
    new-instance made). An object of a framework class may be of a subclass the framework chose (the review of the
    dexfloat-residuals fix: MessageDigest.getInstance returns a provider's subclass, java.security.MessageDigest$Delegate
    on Android 7+, where the VM's object carries the class it was asked for): declines."""
    if desc not in _defined(vm):
        _decline(vm, "getClass of a %s object: its runtime class is not known to the VM" % desc)


def _null_ref(v):
    """True for a null the code made (const/4 0, a null a method returned, an unset field or array slot: an int 0), not
    the None of an entry's argument frame (an unknown receiver the VM stands in for)."""
    return type(v) is int and v == 0


def init_catchall(vm, cls, args):
    """dex_chain_codec.VM._invoke's last resort for a constructor no model takes (it made it a no-op). Only
    java.lang.Object's constructor does nothing on a device; any other runs code the VM does not: it may throw (new
    ArrayList(-1)), call an override the app's subclass declares (Throwable's constructors call fillInStackTrace(),
    Random(long) setSeed(long), ArrayList(Collection) c.toArray(): a field of the app's own class then holds what the
    override wrote, where the VM read 0), or name a class the device does not have (NoClassDefFoundError). Declines
    (the review of the dexfloat-residuals fix: each of those was a WRONG plain under the judged key, as on the tree
    before)."""
    if cls == "Ljava/lang/Object;":
        return
    _decline(vm, "%s.<init>: no model of this constructor, and a device runs it (it may throw, call an override of the "
             "app's, or name a class the device does not have)" % cls)


def _super_target_ok(vm, midx):
    """invoke-super of a body of this dex: ART dispatches it from the CALLING class's superclass (FindSuperMethodToCall),
    so a class between the caller and the method reference's class that declares the method is what a device runs
    (the review of the fix: invoke-super Base.f from Sub, Mid overriding f, ran Base.f). Declines when such a class
    declares it, or when the chain from the caller cannot be followed to the reference's class inside this dex."""
    dex = vm.dex
    owner, name = dex.mname[midx]
    caller = _caller_class(vm)
    if caller is None:
        _decline(vm, "invoke-super %s->%s: the calling class is not known" % (owner, name))
    ci = _ci(dex)
    key = (name, dex._u2(dex.meth_off + midx * 8 + 2))
    info = ci.cls.get(caller)
    c, seen = (info.sup if info is not None else None), set()
    while c != owner:
        ii = ci.cls.get(c) if c is not None else None
        if ii is None or c in seen or c in ci.dup:
            _decline(vm, "invoke-super %s->%s from %s: the superclass chain does not reach %s inside this dex"
                     % (owner, name, caller, owner))
        if key in ii.vmeth:
            _decline(vm, "invoke-super %s->%s from %s: %s declares it, and a device runs that one" % (owner, name,
                                                                                                 caller, c))
        seen.add(c)
        c = ii.sup


def _base_invoke(vm, op, midx, cls, name, args):
    """invoke() on a VM on the base VM's semantics (the split reading, split_bundle.SplitVM): the base VM's models
    answer, except the two restrictions of the dexfloat-residuals fix, which hold there too:
      - Class.forName(name, initialize, loader) declines unless the loader is null and the class certain on the boot
        class path (_forname_loader; the base VM ignored the loader and resolved an app class through the bootstrap
        loader);
      - a method with no body in the running dex of a class that is not the framework's (_framework: an app class of
        any package, of another dex of the bundle or of none, a Lkotlin/ or Landroidx/ class the split reading treats
        as framework, a boot package's class a dex of the bundle defines) declines, but where the base VM's native path
        takes it, as in the full VM (R3): the base VM made such a constructor a no-op (a field it sets read 0, where a
        device ran the body of another dex, or threw NoClassDefFoundError for a class no dex defines) and matched the
        class to String/Integer/... by the end of its name. SplitVM reaches this only after its own resolution (a body
        of this dex, tier C's body in another split, a hook, a native symbol) did not take the call.
    And the 1-argument Class.forName(name) declines a name ART refuses (a slash, a descriptor form) or a class neither
    the bundle's dexes nor the boot class path certainly hold (the review of the fix: forName of a hook framework's
    class went on, where a device throws ClassNotFoundException; the base VM made a token of any name)."""
    if cls == "Ljava/lang/Class;" and name == "forName":
        nm = _G(vm)["_as_text"](args[0]) if args else None
        desc = _desc_of(nm)
        if len(args) == 3:
            _forname_loader(vm, args, desc, nm)
        elif desc is None or not (desc in _defined(vm) or _boot_loadable(vm, desc)):
            _decline(vm, "Class.forName(%r): not a class the bundle or the boot class path certainly holds "
                     "(ClassNotFoundException on a device)" % (nm,))
        return False, None
    if not _framework(vm, cls) and (name == "<init>" or _boot_shadow(cls) or not _native_route(vm, cls, name)):
        _decline(vm, "%s->%s has no body in this dex (a class of another dex, of a library the app ships, or one the "
                 "device may not have): the device runs code the split reading's VM does not see" % (cls, name))
    _suffix_guard(vm, cls, "%s->%s" % (cls, name))
    _spec_guard(vm, cls, name, args)
    return False, None


# the NDK's public system libraries, loadable by any app without shipping them
_NDK_PUBLIC = frozenset(("c", "m", "dl", "log", "z", "android", "jnigraphics", "GLESv1_CM", "GLESv2", "GLESv3", "EGL",
                         "OpenSLES", "OpenMAXAL", "mediandk", "vulkan", "camera2ndk", "nativewindow", "aaudio", "sync",
                         "neuralnetworks", "binder_ndk", "amidi"))


_LOG_LEVELS = ("v", "d", "i", "w", "e")
_STR = "Ljava/lang/String;"


class Opaque:
    """A value the device computes and the VM does not know (the int Log.d returns: the bytes it wrote). Any
    observation of it declines: a comparison (if-eqz, if-eq, ...), arithmetic, a truth value, a hash, its text, a
    number of it."""
    __slots__ = ("what", "_no")

    def __init__(self, decline, what):
        self.what = what
        self._no = decline

    def _refuse(self, *_a, **_k):
        raise self._no("%s is not known to the VM" % self.what)

    __eq__ = __ne__ = __lt__ = __le__ = __gt__ = __ge__ = _refuse
    __hash__ = __bool__ = __str__ = __format__ = __int__ = __index__ = __float__ = __len__ = __iter__ = _refuse
    __add__ = __radd__ = __sub__ = __rsub__ = __mul__ = __rmul__ = __and__ = __rand__ = __or__ = __ror__ = _refuse
    __xor__ = __rxor__ = __lshift__ = __rlshift__ = __rshift__ = __rrshift__ = __mod__ = __rmod__ = _refuse
    __floordiv__ = __rfloordiv__ = __truediv__ = __rtruediv__ = __neg__ = __pos__ = __invert__ = __abs__ = _refuse

    def __repr__(self):
        return "<%s>" % self.what


def _log(vm, midx, name, args):
    """android.util.Log.v/d/i/w/e(String tag, String msg[, Throwable tr]): writes the log and returns how many bytes
    it wrote, which the VM does not know (an Opaque). Only with a message that is known text (a null one throws
    NullPointerException) and no Throwable (its text may run app code); a common line in a <clinit> (review of
    4917e79) and in an entry, so it is modelled where the VM before this module declined: OPS."""
    G = _G(vm)
    text = G["_as_text"]
    _sh, ptypes = _proto(vm.dex, midx)
    if ptypes not in ([_STR, _STR], [_STR, _STR, "Ljava/lang/Throwable;"]) or len(args) != len(ptypes):
        _decline(vm, "Log.%s overload %r is not modelled" % (name, ptypes))
    if not (_is_null(args[0]) or text(args[0]) is not None):
        _decline(vm, "Log.%s with a tag that is not known text" % name)
    if text(args[1]) is None:
        _decline(vm, "Log.%s with a message that is not known text (a null one throws NullPointerException)" % name)
    if len(args) == 3 and not _is_null(args[2]):
        _decline(vm, "Log.%s with a Throwable (its stack trace text may run app code)" % name)
    _feat(vm, OPS)
    return Opaque(G["_Decline"], "the int Log.%s returns" % name)


def _native_route(vm, cls, name):
    """True when dex_chain_codec.VM._invoke's native path would take this call: its own test (a FUNC symbol of a
    shipped ELF64 library ending in `_<name>`, beside a class or symbol name that says native or JNI)."""
    syms = getattr(vm, "native_syms", None)
    if not syms:
        return False
    want = "_" + name
    native_cls = "native" in cls.lower()
    return any(s.endswith(want) and (native_cls or "jni" in s.lower() or s.startswith("Java_")) for s in syms)


def invoke(vm, op, midx, cls, name, args):
    """(handled, result) for the library methods this module models or must refuse; (False, None) leaves the call
    to the rest of dex_chain_codec.VM._invoke, unchanged."""
    if _base(vm):
        return _base_invoke(vm, op, midx, cls, name, args)
    if not _framework(vm, cls):
        # an app class's method with no body in this dex (VM._invoke runs every body the dex has before asking here): a
        # constructor or method of a class another dex member defines, or of one the device may not have. The device
        # runs it (or throws) and the VM does not see it: it declines, where the base VM made a constructor a no-op (an
        # object whose constructor sets a field read 0, a WRONG plain under the judged key: review of 5ffe7f3, R3) and
        # matched an app class to String/Integer/Long/... by the end of its name. Only the base VM's native path goes on
        # (a constructor is never native). Since the dexfloat-residuals fix also a class under a framework package that a
        # dex of the delivery defines, and every Lkotlin/, Lkotlinx/, Landroidx/ class (_framework): before, a Lkotlin/
        # class of classes2.dex had its constructor read as a no-op, a WRONG plain under the judged key. Under a boot
        # package (_boot_shadow) not even the native path goes on: the base VM's native path skips a boot class and its
        # models would take the class for the framework's.
        if name == "<init>" or _boot_shadow(cls) or not _native_route(vm, cls, name):
            hit, out = _cross_static(vm, op, midx, cls, name, args)    # B-249: a pure static of another dex member
            if hit:
                return True, out
            _decline(vm, "%s->%s has no body in this dex (a class of another dex member, or one the device may not "
                     "have): the device runs code the VM does not see" % (cls, name))
        # Reaching here, _native_route is True, so _so_first binds a symbol and the base VM's native path takes the
        # call: it returns the body's reading or raises (so-ambig, an unmodelled machine, an L/F/D return). It never
        # falls through to the java.lang-by-suffix models in _invoke_legacy's tail (first-is-None is the `not
        # _native_route` decline above), so a _suffix_guard decline here would never stop a real suffix model -- it
        # would only suppress a genuine native reading of a class named like a java.lang one (e.g. a jlong native of
        # Lcom/.../HexLong;), demoting its +jni-long attribution to +native-image. The native path keeps the call.
        return False, None
    _suffix_guard(vm, cls, "%s->%s" % (cls, name))
    _spec_guard(vm, cls, name, args)
    if cls in _SB_CLASSES or cls == _STR:
        hit, out = _text_extra(vm, midx, cls, name, args)        # B-249: the TEXT subset
        if hit:
            return True, out
    if cls == "Ljava/lang/Float;" or cls == "Ljava/lang/Double;":
        _feat(vm, FLOAT)
        return _float_lib(vm, op, cls, name, vm.dex.meth_shorty(midx), args)
    if cls == "Ljava/lang/Math;" or cls == "Ljava/lang/StrictMath;":
        _feat(vm, FLOAT)
        return _math_lib(vm, op, name, vm.dex.meth_shorty(midx), args)
    if cls in _REFLECT_CLASSES:
        return _reflect(vm, op, cls, name, args, None)
    if cls == "Landroid/util/Log;" and name in _LOG_LEVELS and op in INVOKE_STATIC:
        return True, _log(vm, midx, name, args)
    if cls == "Ljava/lang/System;" and name == "loadLibrary":
        lib = _G(vm)["_as_text"](args[0]) if args else None
        if lib is None:
            _decline(vm, "System.loadLibrary of a non-text name")
        ext = _ext(vm)
        if ext is not None and ("lib%s.so" % lib) not in ext["libs"] and lib not in _NDK_PUBLIC:
            # UnsatisfiedLinkError on the device (the `try { loadLibrary("frida-gadget") } catch` probe): the VM takes
            # no catch path
            _decline(vm, "System.loadLibrary(%r): the package ships no lib%s.so" % (lib, lib))
        syms = list(getattr(vm, "native_syms", {}) or {}) + list(getattr(vm, "native_arm", {}) or {})
        st = _st(vm)
        if any(s == "JNI_OnLoad" for s in syms):
            # JNI_OnLoad may write statics and RegisterNatives may rebind natives: inside a <clinit> this taints the
            # static store (ensure_init catches it); in the chain's own code it declines, as before this module
            st.taint = st.taint or "System.loadLibrary ran a JNI_OnLoad (it may write statics or rebind natives)"
            _decline(vm, "System.loadLibrary with a JNI_OnLoad in the package")
        if ext is None or ("lib%s.so" % lib) in ext["libs"]:
            # a library the package ships (or may: a bare dex): the symbols above miss a JNI_OnLoad of a 32-bit library
            # (the ELF readers take ELF64 only), one with no symbol size, one written in assembly, and its constructors
            # (.init_array) run at the load too. Whatever it runs may write statics, also one the run stored last: every
            # later static read declines (review of 5ffe7f3, R2). A public NDK library the package does not ship is the
            # system's own, which runs no app code.
            st.taint = st.taint or ("System.loadLibrary(%r): the library's JNI_OnLoad or constructors, which the VM "
                                    "does not run, may write statics" % lib)
        if st.depth == 0:
            _feat(vm, STATIC)                     # before this module a loadLibrary in the chain declined
        return True, None
    if cls == "Ljava/lang/StringBuilder;" or cls == "Ljava/lang/StringBuffer;":
        return _sb_guard(vm, midx, name, args)
    if cls == "Ljava/lang/String;":
        return _string_guard(vm, op, midx, name, args)
    if cls == "Ljava/lang/Integer;" and name == "parseInt" and op in INVOKE_STATIC:
        t = _G(vm)["_as_text"](args[0]) if args else None
        radix = args[1] if len(args) > 1 else 10
        if not isinstance(radix, int) or java_parse_int(t, radix, 32) is None:
            # Python's int() accepts whitespace, underscores, 0x/0o/0b prefixes and any size, which the VM's model
            # then wrapped to 32 bits: Java throws NumberFormatException on each, and the VM takes no catch path
            _decline(vm, "Integer.parseInt(%r, %r): NumberFormatException on the device" % (t, radix))
        return False, None
    if cls in _GUARDED:
        _decline(vm, "%s is not modelled" % cls)
    if cls in _BOX_OF and args and op not in INVOKE_STATIC:
        b = args[0]
        Box = _G(vm)["_Box"]
        if isinstance(b, Box) and b.t != _BOX_OF[cls]:
            # the call's class is the receiver's static type (a check-cast before it, which the VM does not model):
            # a box of another type would have thrown ClassCastException there
            _decline(vm, "%s.%s on a %s box (Java throws ClassCastException)" % (cls, name, b.t))
    return False, None


# ---------------------------------------------------------------------- Java text of values the VM can render exactly
def float_text(bits, is_float):
    """Float.toString / Double.toString (and String.valueOf, StringBuilder.append) ONLY where every Java runtime
    Android ships prints the same text: NaN, the infinities, the signed zeros and integral values of magnitude below
    10^7 ("123.0"; the specification prints the whole integer part there and one fractional digit, and the old
    FloatingDecimal, Harmony's RealToString and the JDK 19 shortest algorithm agree). None for anything else (their
    digit choices differ elsewhere, JDK-4511638), and the VM declines."""
    v = f32(bits) if is_float else f64(bits)
    if v != v:
        return "NaN"
    if math.isinf(v):
        return "Infinity" if v > 0 else "-Infinity"
    if v == 0.0:
        return "-0.0" if math.copysign(1.0, v) < 0 else "0.0"
    if abs(v) < 1e7 and v == math.floor(v):
        return "%d.0" % int(v)
    return None


def _box_text(vm, v):
    """String.valueOf(Object) of a box the VM holds, exactly as Java renders it, or None."""
    G = _G(vm)
    if not isinstance(v, G["_Box"]):
        return None
    if v.t in ("I", "S", "B"):
        return str(_s32(v.v))
    if v.t == "J":
        return str(_s64(v.v))
    if v.t == "C":
        return chr(v.v & 0xFFFF)
    if v.t == "Z":
        return "true" if v.v else "false"
    if v.t in ("F", "D"):
        return float_text(v.v, v.t == "F")
    return None


def _is_null(v):
    return v is None or (type(v) is int and v == 0)


def java_parse_int(text, radix, bits):
    """Integer.parseInt (bits 32) / Long.parseLong (64): the value, or None where Java throws NumberFormatException,
    or where the VM will not decide: radix 2..36, an optional leading '+' or '-', then one or more ASCII digits of the
    radix (Java also takes other Unicode digits; those are left to decline), in range."""
    if not isinstance(text, str) or not text or not 2 <= radix <= 36:
        return None
    s = text
    neg = s[0] == "-"
    if s[0] in "+-":
        s = s[1:]
    if not s:
        return None
    v = 0
    for ch in s:
        c = ord(ch)
        if 48 <= c <= 57:
            dg = c - 48
        elif 97 <= c <= 122:
            dg = c - 87
        elif 65 <= c <= 90:
            dg = c - 55
        else:
            return None
        if dg >= radix:
            return None
        v = v * radix + dg
    v = -v if neg else v
    return v if -(1 << (bits - 1)) <= v <= (1 << (bits - 1)) - 1 else None


def _sb_guard(vm, midx, name, args):
    """StringBuilder/StringBuffer: the overloads the VM's own model gets wrong are rendered exactly here or declined
    (append(boolean) appended U+0000/U+0001, append(null) "" or U+0000, append(Object) of a box its Python repr,
    append(char[]/CharSequence, int, int) ignored the range, insert(int, int/long) a character, an index out of range
    was clamped or wrapped where Java throws). Everything else is left to the VM's model unchanged."""
    G = _G(vm)
    if name not in ("append", "insert", "charAt", "setCharAt", "setLength", "<init>"):
        return False, None
    sb = args[0] if args else None
    if not isinstance(sb, G["_SB"]):
        return False, None
    if name == "<init>":
        if len(args) >= 2:
            sh = vm.dex.meth_shorty(midx)
            v = args[1]
            if not isinstance(sh, str):
                return False, None                    # no proto here: the VM's model as before
            if sh == "VI":
                if not isinstance(v, int) or v < 0:
                    _decline(vm, "new StringBuilder(negative capacity) throws NegativeArraySizeException")
            elif sh != "VL":
                _decline(vm, "new StringBuilder overload %s is not modelled" % sh)
            elif _is_null(v):
                _decline(vm, "new StringBuilder(null) throws NullPointerException")
            elif G["_as_text"](v) is None:
                _decline(vm, "new StringBuilder(...) of a value whose text is not modelled")
        return False, None
    if name in ("charAt", "setCharAt"):
        i = args[1] if len(args) > 1 else None
        if not isinstance(i, int) or not 0 <= i < sum(len(p) for p in sb.parts):
            _decline(vm, "StringBuilder.%s index out of range (Java throws)" % name)
        return False, None
    if name == "setLength":
        n = args[1] if len(args) > 1 else None
        if not isinstance(n, int) or not 0 <= n <= sum(len(p) for p in sb.parts):
            _decline(vm, "StringBuilder.setLength beyond the length pads with U+0000 (not modelled) or throws")
        return False, None
    sh, ptypes = _proto(vm.dex, midx)
    text = G["_as_text"]
    if not isinstance(sh, str):
        return False, None                            # no proto here: the VM's model as before
    if name == "insert":
        if len(sh) != 3 or sh[1] != "I":
            _decline(vm, "StringBuilder.insert overload %s is not modelled" % sh)
        i = args[1] if len(args) > 1 else None
        if not isinstance(i, int) or not 0 <= i <= sum(len(p) for p in sb.parts):
            _decline(vm, "StringBuilder.insert offset out of range (Java throws)")
        p = sh[2]
        v = args[2] if len(args) > 2 else None
        if p == "C":
            return False, None
        if p in ("L", "["):                           # "[": a hand-built fixture's shorty for an array parameter
            pt = ptypes[1] if ptypes is not None and len(ptypes) > 1 else None
            if (pt == "[C" or p == "[") and isinstance(v, list) and all(isinstance(c, int) for c in v):
                return False, None
            if pt in (None, "Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;") \
                    and text(v) is not None:
                return False, None
        _decline(vm, "StringBuilder.insert(int, %s) of this value is not modelled" % p)
    # append
    if len(sh) != 2:
        _decline(vm, "StringBuilder.append overload %s (a range or several arguments) is not modelled" % sh)
    p = sh[1]
    v = args[1] if len(args) > 1 else None
    if p == "[":                                      # a hand-built fixture's shorty for an array parameter
        if isinstance(v, list) and all(isinstance(c, int) for c in v):
            return False, None
        _decline(vm, "StringBuilder.append(array) of a null or non-char array")
    if p in ("I", "J", "C", "S", "B"):
        return False, None
    if p == "Z":
        if not isinstance(v, int):
            _decline(vm, "StringBuilder.append(boolean) of a non-number")
        sb.parts.append("true" if v else "false")
        _feat(vm, OPS)
        return True, sb
    if p in ("F", "D"):
        t = float_text(v, p == "F") if isinstance(v, int) else None
        if t is None:
            _decline(vm, "StringBuilder.append(%s): Java's text of this value differs between runtimes" % p)
        sb.parts.append(t)
        _feat(vm, FLOAT)
        return True, sb
    if p != "L":
        _decline(vm, "StringBuilder.append(%s)" % p)
    pt = ptypes[0] if ptypes is not None and ptypes else None
    if pt == "[C":
        if isinstance(v, list) and all(isinstance(c, int) for c in v):
            return False, None
        _decline(vm, "StringBuilder.append(char[]) of a null or non-char array (Java throws)")
    if text(v) is not None and pt in (None, "Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;",
                                      "Ljava/lang/StringBuffer;"):
        return False, None
    if pt in ("Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;", "Ljava/lang/StringBuffer;"):
        if _is_null(v):
            sb.parts.append("null")
            _feat(vm, OPS)
            return True, sb
        if pt == "Ljava/lang/Object;":
            t = _box_text(vm, v)
            if t is not None:
                sb.parts.append(t)
                _feat(vm, FLOAT if v.t in ("F", "D") else OPS)
                return True, sb
    _decline(vm, "StringBuilder.append(%s) of a value whose Java text is not modelled" % (pt or p))


def _string_guard(vm, op, midx, name, args):
    """String: valueOf(float/double) rendered where exact (float_text), valueOf(Object) of an array declined (Java prints
    its identity), and the index checks Java makes where Python would wrap or clamp (charAt, substring, indexOf)."""
    G = _G(vm)
    if name == "valueOf" and op in INVOKE_STATIC:
        sh, ptypes = _proto(vm.dex, midx)
        if sh in ("LF", "LD"):
            v = args[0] if args else None
            t = float_text(v, sh == "LF") if isinstance(v, int) else None
            if t is None:
                _decline(vm, "String.valueOf(%s): Java's text of this value differs between runtimes" % sh[1])
            _feat(vm, FLOAT)
            return True, t
        if sh == "LL" and ptypes is not None and ptypes and ptypes[0] == "Ljava/lang/Object;":
            v = args[0] if args else None
            if G["_as_text"](v) is None:
                if _is_null(v):
                    _feat(vm, OPS)
                    return True, "null"
                t = _box_text(vm, v)
                if t is None:
                    _decline(vm, "String.valueOf(Object) of a value whose Java text is not modelled")
                _feat(vm, FLOAT if v.t in ("F", "D") else OPS)
                return True, t
        return False, None
    if op in INVOKE_STATIC or not args:
        return False, None
    s = G["_as_text"](args[0])
    if s is None:
        return False, None
    if name == "charAt":
        i = args[1] if len(args) > 1 else None
        if not isinstance(i, int) or not 0 <= i < len(s):
            _decline(vm, "String.charAt index out of range (Java throws)")
    elif name == "substring":
        b = args[1] if len(args) > 1 else None
        e = args[2] if len(args) > 2 else len(s)
        if not (isinstance(b, int) and isinstance(e, int) and 0 <= b <= e <= len(s)):
            _decline(vm, "String.substring range out of bounds (Java throws)")
    elif name == "indexOf" and len(args) > 2:
        f = args[2]
        if not isinstance(f, int) or f < 0:
            _decline(vm, "String.indexOf with a negative start (Python would count from the end)")
    return False, None


def _not_duplicated(vm, desc):
    ext = _ext(vm)
    if ext is not None and desc in ext.get("dup", ()):
        _decline(vm, "class %s is defined by more than one dex of the package (the device runs one copy)" % desc)


def pre_entry(vm, midx):
    """Before an ANS entry runs (dex_chain_codec.codes_in_dex_ex): its class must not be one another dex member also
    defines (that copy may be dead on the device), nor a class under a boot class path package (a device may run the
    boot copy: _boot_shadow)."""
    if _base(vm):
        return
    mn = vm.dex.mname.get(midx)
    if mn is not None:
        _not_duplicated(vm, mn[0])
        _no_shadow(vm, mn[0], "the entry %s" % mn[1])


def pre_invoke(vm, op, midx, args):
    """Before any invoke: JVM class initialization for invoke-static; refuse a native float/double signature, a body
    of a class another dex member also defines, and a virtual call whose receiver's class overrides the method (the VM
    dispatches statically)."""
    if _base(vm):
        return
    if op not in INVOKE_STATIC and args and _null_ref(args[0]):
        # (the review of the dexfloat-residuals fix) an instance method on a null receiver: a device throws
        # NullPointerException at the invoke, the VM ran the body (a constant code came out)
        mn = vm.dex.mname.get(midx) or vm.dex.meth(midx)
        _decline(vm, "%s->%s on a null receiver (NullPointerException on a device)" % mn)
    if (op == 0x6f or op == 0x75) and midx in vm.dex.code:
        _super_target_ok(vm, midx)                 # per call: the dispatch depends on the calling class
    st = None
    if op not in INVOKE_VIRTUAL:
        st = _st(vm)
        if midx in st.pre_ok:                      # passed before in this run, and nothing it checks can change
            return
    dex = vm.dex
    code = dex.code
    if midx in code:
        owner = dex.mname[midx][0]
        _not_duplicated(vm, owner)
        if owner.startswith(_BOOT_PKGS):
            # a body of this dex for a class under a boot class path package (this dex defines it): a device runs the
            # boot copy where its boot class path holds the class (parent-first), and this body only where it does not
            _no_shadow(vm, owner, "%s->%s" % (owner, dex.mname[midx][1]))
    if op == 0x71 or op == 0x77:
        mn = dex.mname.get(midx)
        if mn is None:
            mn = dex.meth(midx)
        ensure_init(vm, mn[0])                     # once; a class that failed to initialize declines
        if st.init.get(mn[0]) not in ("done", "ext"):
            st = None                              # its <clinit> is still running: not settled yet
    elif op in INVOKE_VIRTUAL and midx in code and args:
        recv = args[0]
        Obj = _G(vm)["_Obj"]
        if isinstance(recv, Obj):
            owner = dex.mname[midx][0]
            if recv.type != owner:
                ci = _ci(dex)
                key = (dex.mname[midx][1], dex._u2(dex.meth_off + midx * 8 + 2))
                c, seen = recv.type, set()
                while c != owner:
                    info = ci.cls.get(c)
                    if info is None or c in seen:
                        # the receiver's class chain leaves this dex (or an interface's default method): a class
                        # the VM cannot see may override the method
                        _decline(vm, "virtual call on %s: the dispatch to %s->%s is not provable here"
                                 % (recv.type, owner, key[0]))
                    seen.add(c)
                    if key in info.vmeth:
                        _decline(vm, "virtual call: %s overrides %s->%s (not dispatched)" % (c, owner, key[0]))
                    c = info.sup
                    if c is None:
                        _decline(vm, "virtual call on %s: %s is not one of its superclasses" % (recv.type, owner))
    if midx not in code and (getattr(vm, "native_syms", None) or getattr(vm, "native_arm", None)):
        mn = dex.mname.get(midx) or dex.meth(midx)
        shorty = getattr(dex, "meth_shorty", None)
        if not _framework(vm, mn[0]) and shorty is not None:
            sh = shorty(midx)
            if isinstance(sh, str) and ("F" in sh or "D" in sh):
                _decline(vm, "native %s->%s passes or returns float/double (FP registers not modelled)" % mn)
    if st is not None:
        st.pre_ok.add(midx)


def exec_extra(vm, op, b1, ins, pc, R):
    """An opcode dex_chain_codec.VM._exec does not handle: the next pc, or None (then it declines)."""
    if _base(vm):
        return None
    if op == 0x1c:                                                  # const-class vAA, type@BBBB
        desc = vm.dex.type_str(ins[pc + 1])
        if not _exists(vm, desc):
            # const-class of a class the device may not have throws NoClassDefFoundError there (a hook framework's
            # class: the probe of Class.forName's, R4), and the VM takes no catch path
            _decline(vm, "const-class of %s: the class may be absent on the device (NoClassDefFoundError)" % desc)
        R[b1] = _cref(vm, desc)
        _feat(vm, REFLECT)
        return pc + 2
    if op in (0x1d, 0x1e):                                          # monitor-enter / monitor-exit vAA
        # one thread: taking and releasing a monitor changes no value. A null (or a number: no reference) throws
        # NullPointerException on the device, and the VM, which takes no catch path, declines.
        # A monitor-exit of a monitor this thread does not hold throws IllegalMonitorStateException: counted per object.
        v = R[b1]
        if v is None or isinstance(v, int):
            _decline(vm, "monitor-%s on a null reference" % ("enter" if op == 0x1d else "exit"))
        vs = _vs(vm)
        held = vs.mon
        if held is None:
            held = vs.mon = {}
        n = held.get(id(v), (0, v))[0]
        if op == 0x1e and n == 0:
            _decline(vm, "monitor-exit of a monitor not held (IllegalMonitorStateException)")
        held[id(v)] = (n + (1 if op == 0x1d else -1), v)    # the object is kept, so its id is never reused
        _feat(vm, OPS)
        return pc + 1
    return None


# ====================================================================== features -> the answer's key
def note(feats, code, vm):
    """Record which new capability families the run that produced `code` used."""
    feats.setdefault(code, []).append(frozenset(_vs(vm).feat or ()))


def families(feats, codes):
    """The families of every run that produced one of `codes`: their UNION. A code some run reached through a new
    capability is never answered under the old key, even when another run produced the same code without one (review
    of 4917e79, S10: a featureless debug entry computing a decoy constant and the real chain reading a decoy default
    through the static store gave one code; the intersection the module took before dropped +dex-static, and the
    decoy went PLAIN under the judged key, where the VM without this module gave two codes)."""
    out = set()
    for c in codes:
        for run in feats.get(c) or ():
            out |= run
    return out


def key_suffix(feats, codes):
    """'' when every code is reachable by the old VM, else '+dex-float', '+dex-float+dex-static', ... (sorted)."""
    fams = families(feats, codes)
    return "".join("+" + f for f in sorted(fams))
