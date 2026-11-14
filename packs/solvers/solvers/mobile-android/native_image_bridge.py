#!/usr/bin/env python3
"""KB-2: the dex VM's bridge to whole-image native emulation (solvers/common/native_image.py).

`dex_chain_codec.VM._invoke` hands every invoke of a method WITHOUT dex code to `invoke()` when the
delivery ships a native library this engine might load (an ELF64 x86-64 or AArch64 file). This module decides,
ART's way, which function (if any) a device runs for the call, and reads it two ways:

  1. the lane's existing reader (`legacy`: the hand-rolled x86-64/AArch64 readers cross-checked with the
     single-function Unicorn engine), asked about EXACTLY the function ART binds: it is called with a native
     symbol table that holds only that symbol, with the bytes of the library that exports it (never the merged
     table, whose loose suffix match could read another class's export or another library's body);
  2. the whole image (native_image.call_jni): sibling calls, PLT/GOT, .rodata/.data tables, the modelled
     libc subset and the fake JNIEnv (String and byte[]/int[] arguments and returns).

Every library that binds the method (ABI variants, a second library exporting the name) must be read by one
engine or the other, and every reading must agree; otherwise the call declines:
  * the legacy reader reads at least one binding body: its value (a narrow int return seen as the method's
    Java type), when the whole image agrees, was not run (a size bound, a cap, an input it does not model), or
    ran out of work (then the reading is demoted, `+image-unchecked`). When the whole image RAN the call and
    failed for any other reason (an unmodelled import or JNI call, an undefined read, state escaping the call, the
    two layouts disagreeing), the two engines did not follow one path (an emulator check on the legacy engine's
    fixed addresses, a NULL JNIEnv test) and the call declines;
  * only the whole image reads it: its value, and the VM is marked, so a code that depends on it is answered
    under a NEW unsure key (`keyed()`: mobile.codec/analysis+native-image, or +native-cstr for a `jstring`
    that is really a C pointer), never under a judged route;
  * neither: the call declines.

ART's rules, kept strictly (each one only restricts):
  * the invoked method is resolved as ART's class linker resolves it, by (class, name, signature) across EVERY
    dex member of the delivery, up the superclass chain of the classes the delivery defines (a call from
    classes.dex to a native classes2.dex declares, or through a subclass reference, binds the DECLARING class's
    method); a method the delivery does not declare native never binds to a native export, and a method the
    delivery does not define at all is the FRAMEWORK's (it runs the VM's framework model with an empty native
    table, so the shipped reader's loose suffix match cannot bind an app export named like it); an ambiguous
    resolution (an override of a native, a static/instance mismatch) declines. A class defined in more than
    one dex member is ONE class when every definition agrees on the method (its flags, its code, its superclass);
    when they differ, the class loader's first main dex member decides and the reading is demoted (`+dup-class`);
  * the symbol is the exact JNI short name, then the long (overloaded) name, of the declaring class and
    method (`MangleForJni`); a name one library defines twice declines;
  * the load phase comes first: the constructors and JNI_OnLoad of each library that could bind the call
    (it holds the call's JNI name or a JNI_OnLoad) run before any call (native_image.load_info). A method a
    JNI_OnLoad binds with RegisterNatives is THAT function, not the exported Java_ symbol: the legacy reader (which
    reads exports) is not asked, and the whole image's answer, under the new unsure key, is the only reading;
  * a declared native that no library registers or exports declines (UnsatisfiedLinkError on a device);
  * DEMOTIONS (the reading stays, never plain until the judge accepts the demoted key): a library this engine
    cannot parse (32-bit ARM, another machine) that holds the name or a JNI_OnLoad adds `+abi-unverified` (which
    ABI a device loads decides the answer); constructors (no JNI_OnLoad) of a binding library that cannot be
    modelled add `+ctor-unverified`; a JNI_OnLoad (in any library that could bind the call) that cannot be
    modelled adds `+onload-unverified@<why>` (what it registers is unknown; <why> names the first thing the
    model could not run, so a name the judge accepts for one kind of JNI_OnLoad does not answer another); an
    ELF64 x86-64/AArch64 library a device loads but this engine does not (past its bounds: over 32 MiB, too many
    relocations, a W+X segment) that holds the name adds `+lib-unverified` (the legacy reader reads its export
    unchecked), one with a JNI_OnLoad `+onload-unverified@unloadable` (one no loader accepts at all, with no
    program headers or no PT_LOAD, is read by the legacy reader as before this build; a library over the size
    bound that could bind the call only through its load phase is `+onload-unverified@size` without being
    parsed); a class defined twice with differing definitions adds `+dup-class`;
  * a zero / NULL return is the "denied" sentinel (the gate-FAIL leg of Day 25), as the legacy reader treats
    a zero x86-64 return: an image-only reading of it declines, so a decoy chain never assembles a code from it.

Bounded by work, never by a clock: each run of a call has a block and a memory-access budget, and one
delivery's calls share a total, a cap on whole-image evaluations and a budget of image bytes mapped (each run
maps the whole image; a load phase's two runs are charged to it too); its load phases share a work budget of their
own, and the two runs of a call or of a load phase share what is left (the second gets what the first left).
Identical calls are evaluated once per delivery (calls are order-free: no state escapes one). Past a budget, or
when the image is not asked for any reason but a load phase it cannot model (a size bound, an image problem, an
input it does not model), a reading the legacy reader proves for every binding library stands only DEMOTED
(`+image-unchecked@<method>`: fix round 2, the review of 4250749), never plain; an image-only call declines.
Libraries are parsed only when a call could bind to them, and parsed images, load phases, legacy symbol tables and
evaluations are cached by content for the process, each charged to the delivery's budgets exactly as when it was
computed, so a warm process answers what a cold one answers.

THE PORT ONTO SO-AMBIG (fix round 2): dex_chain_codec's so-ambig binding rules are a second gate (`_gate`). The
bridge asks them about every native reading (dex_chain_codec._so_verdict, over the delivery's whole table) and
declines every call they decline (two .so bodies of one machine, an exact-name conflict, an export no loader
returns, an opaque body, a JNI_OnLoad not proven inert, DT_INIT / DT_INIT_ARRAY, a machine no emulator models),
whatever the whole image read, its RegisterNatives binding included; where they bind the call, its binding must be
the export they bind and every body the legacy reader read one they bind. A RegisterNatives binding by two
libraries of one machine declines. A plain answer stands only where both rule sets allow it.
"""
import hashlib
import re
import struct
import sys

try:
    import native_image as _ni
except Exception as _e:                 # engine missing: the bridge is inert (the legacy path alone), said by name (B-240)
    import warnings
    warnings.warn("native_image_bridge: native_image is unavailable (%s: %s); whole-image emulation is OFF "
                  "for this process" % (type(_e).__name__, _e), RuntimeWarning)
    _ni = None

ROUTE_IMAGE = "+native-image"
ROUTE_CSTR = "+native-cstr"
FLAG_ABI = "+abi-unverified"
FLAG_CTOR = "+ctor-unverified"
FLAG_ONLOAD = "+onload-unverified"      # always with "@<why>" (KB-2 fix round 1)
FLAG_DUP = "+dup-class"
FLAG_LIB = "+lib-unverified"
FLAG_UNCHECKED = "+image-unchecked"
FLAG_LONG = "+jni-long"                 # a native bound by its long (overloaded) JNI name only (the port onto so-ambig)
_DEMOTIONS = (FLAG_ABI, FLAG_CTOR, FLAG_ONLOAD, FLAG_DUP, FLAG_LIB, FLAG_UNCHECKED, FLAG_LONG)   # their order
ACC_STATIC = 0x8
ACC_NATIVE = 0x100
NO_INDEX = 0xFFFFFFFF
STATIC_OPS = (0x71, 0x77)                         # invoke-static, invoke-static/range
DIRECT_OPS = (0x70, 0x76)                         # invoke-direct
VIRTUAL_OPS = (0x6E, 0x6F, 0x72, 0x74, 0x75, 0x78)   # invoke-virtual/super/interface (+ /range)
PER_RUN_BLOCKS = 20_000
PER_RUN_MEM = 100_000
TOTAL_BLOCKS = 40_000                   # per delivery (one codes_in_dex_ex call), both runs counted
TOTAL_MEM = 300_000
MAX_IMAGE_CALLS = 16                    # whole-image evaluations per delivery (an identical call is evaluated once)
TOTAL_SETUP_BYTES = 32 << 20            # image bytes mapped per delivery (each run maps its library's whole span)
MAX_LOAD_PHASES = 8                     # load phases (constructors, JNI_OnLoad) run per delivery
TOTAL_LOAD_BLOCKS = 4 * 2 * PER_RUN_BLOCKS
TOTAL_LOAD_MEM = 4 * 2 * PER_RUN_MEM
# A library past these sizes is not emulated here (its per-call setup would not fit a timed set): a call into it
# is the legacy reading alone, as before this build, and a load phase of it counts as one that cannot be modelled.
MAX_IMAGE_BYTES = 8 << 20
MAX_IMAGE_SPAN = 16 << 20
MAX_IMAGE_RELOCS = 20_000
M64 = (1 << 64) - 1
_LAUNCHER = re.compile(r"classes(\d*)\.dex")      # the members the app's own class loader loads (fullmatch)
_ODD = 1 << 30                                    # the place of a dex the class loader does not order
_LOADABLE = (62, 183)                             # EM_X86_64, EM_AARCH64

_LEGACY_CODES = set()
_IMAGE_CODES = {}                       # code -> frozenset of route flags (+native-image, +abi-unverified, ...)


def available():
    return _ni is not None and _ni.UNICORN_AVAILABLE


def _too_big(img):
    return len(img.data) > MAX_IMAGE_BYTES or (img.hi - img.lo) > MAX_IMAGE_SPAN or len(img.plan) > MAX_IMAGE_RELOCS


# --------------------------------------------------------------------------------------- process caches
# Everything here is keyed by CONTENT (a SHA-256 of the bytes), never by an object's id, and every entry that cost
# work records that work, so a delivery's budgets are charged the same whether an answer was computed or found.
_DIGESTS = {}           # id(bytes) -> (that bytes object, its sha256): held, so the id cannot be reused while cached
_DIGEST_HELD = [0]
_DIGEST_MAX = 256 << 20
_HOLDS = {}             # (sha256, needle) -> bool
_VIEWS = {}             # sha256 -> _DexView
_FACTS = {}             # members key -> (classes, natives)
_LOADS = {}             # (sha256, classes, natives, max_blocks, max_mem) -> (registered, error, blocks, mem)
_EVALS = {}             # content key of one evaluation -> (outcome, blocks, mem)
_BODIES = {}            # sha256 -> the legacy reader's symbol table of that library
_ARMS = {}              # sha256 -> its AArch64 function table


def _put(cache, key, value, cap):
    cache[key] = value
    while len(cache) > cap:
        cache.pop(next(iter(cache)))
    return value


def clear_caches():
    """Forget every process cache (tests that count evaluations start from here)."""
    for c in (_DIGESTS, _HOLDS, _VIEWS, _FACTS, _LOADS, _EVALS, _BODIES, _ARMS):
        c.clear()
    _DIGEST_HELD[0] = 0


def _digest(raw):
    got = _DIGESTS.get(id(raw))
    if got is not None and got[0] is raw:
        return got[1]
    h = hashlib.sha256(raw).digest()
    if isinstance(raw, bytes) and len(raw) <= _DIGEST_MAX:
        _DIGESTS[id(raw)] = (raw, h)
        _DIGEST_HELD[0] += len(raw)
        while _DIGEST_HELD[0] > _DIGEST_MAX and _DIGESTS:
            old = _DIGESTS.pop(next(iter(_DIGESTS)))
            _DIGEST_HELD[0] -= len(old[0])
    return h


def _img_digest(img):
    h = getattr(img, "content_digest", None)
    if h is None:
        h = hashlib.sha256(img.data).digest()
        try:
            img.content_digest = h
        except Exception:
            pass
    return h


def _holds(h, raw, needle):
    """True when `raw` (content key `h`) holds the bytes `needle` (a name and its NUL): a name the dynamic linker
    can find in a library is a NUL-terminated string of its file, so a library that does not hold it can neither
    export it nor be the one whose JNI_OnLoad ART calls."""
    key = (h, needle)
    got = _HOLDS.get(key)
    if got is None:
        got = _put(_HOLDS, key, needle in raw, 4096)
    return got


def _elf64_machine(raw):
    """e_machine of an ELF64 little-endian file, else None (read from the header alone)."""
    if len(raw) >= 20 and raw[:4] == b"\x7fELF" and raw[4] == 2 and raw[5] == 1:
        return struct.unpack_from("<H", raw, 18)[0]
    return None


def _device_refuses(raw):
    """True when every dynamic loader refuses this ELF64 file outright (no loadable type, no program headers, no
    PT_LOAD): no device runs any of it, its exports or its JNI_OnLoad. Such a file is a fixture's shortcut, read by
    the legacy reader alone as before this build. (A W+X segment is not such a refusal: Android before 8.0 loads it
    with a warning.)"""
    try:
        if struct.unpack_from("<H", raw, 16)[0] not in (2, 3):
            return True
        phoff = struct.unpack_from("<Q", raw, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", raw, 0x36)
        if phentsize != 56 or not phnum or phoff + 56 * phnum > len(raw):
            return True
        return not any(struct.unpack_from("<I", raw, phoff + 56 * i)[0] == 1 for i in range(phnum))
    except Exception:
        return True


def _slug(text, n=40):
    return re.sub(r"[^a-z0-9_-]+", "-", str(text).lower()).strip("-")[:n] or "other"


def _reason_tag(err):
    """A short, stable name for why a load phase could not be modelled (the first thing it met), for the
    +onload-unverified key."""
    text = str(err)
    if _ni is not None and isinstance(err, _ni.BudgetError):
        return "budget"
    for prefix, tag in (("call to unresolved import ", "import-"), ("JNI function ", "jni-"),
                        ("JavaVM function ", "vm-"), ("libc function ", "libc-")):
        if text.startswith(prefix):
            return _slug(tag + text[len(prefix):].split(" ", 1)[0])
    for prefix, tag in (("FindClass(", "findclass"), ("RegisterNatives", "registernatives"),
                        ("JNI_OnLoad returned", "version"), ("the library is too large", "size"),
                        ("the delivery's load-phase", "budget")):
        if text.startswith(prefix):
            return tag
    if _ni is not None and isinstance(err, _ni.SetupError):
        return "setup"
    return "other"


# --------------------------------------------------------------------------------------- JNI names
def mangle(s):
    """ART's MangleForJni of a class (with '/') or method name, or of a parameter signature."""
    out = []
    for ch in s:
        if ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ("0" <= ch <= "9"):
            out.append(ch)
        elif ch in "./":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            raw = ch.encode("utf-16-le", "surrogatepass")
            for k in range(0, len(raw), 2):
                out.append("_0%04x" % struct.unpack_from("<H", raw, k)[0])
    return "".join(out)


def jni_names(cls_desc, name, params):
    """(short name, long name) ART looks up for a native method, or None for a malformed class."""
    if not (isinstance(cls_desc, str) and cls_desc.startswith("L") and cls_desc.endswith(";")):
        return None
    short = "Java_" + mangle(cls_desc[1:-1]) + "_" + mangle(name)
    long_ = short + "__" + mangle("".join(params)) if params is not None else None
    return short, long_


# --------------------------------------------------------------------------------------- dex facts
def _uleb(d, o):
    r = s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, o
        s += 7


def proto(dex, midx):
    """(return descriptor, [parameter descriptors]) of a method, or None when the proto is absent or does
    not agree with its own shorty (a hand-built fixture without return/parameter types)."""
    try:
        if not dex.proto_off or not dex.proto_size:
            return None
        pidx = dex._u2(dex.meth_off + midx * 8 + 2)
        if pidx >= dex.proto_size:
            return None
        sh_idx, rt_idx, par = struct.unpack_from("<III", dex.d, dex.proto_off + pidx * 12)
        shorty = dex.string(sh_idx)
        ret = dex.type_str(rt_idx)
        params = []
        if par:
            n = dex._u4(par)
            if n > 255:
                return None
            params = [dex.type_str(dex._u2(par + 4 + 2 * k)) for k in range(n)]
        sig = [ret] + params
        if len(shorty) != len(sig):
            return None
        for s, t in zip(shorty, sig):
            if (s == "L") != (t[:1] in ("L", "[")) or (s != "L" and t != s):
                return None
        return ret, params
    except Exception:
        return None


def _sig(pr):
    return None if pr is None else "(" + "".join(pr[1]) + ")" + pr[0]


def native_methods(dex):
    """Method indices declared ACC_NATIVE in this dex's class data (cached on the Dex)."""
    got = getattr(dex, "_kb2_native", None)
    if got is not None:
        return got
    out = set()
    try:
        for (_desc, _sup, off) in _class_heads(dex):
            for (mi, fl, _code) in _class_methods(dex, off):
                if fl & ACC_NATIVE:
                    out.add(mi)
    except Exception:
        out = set()
    try:
        dex._kb2_native = out
    except Exception:
        pass
    return out


def _class_heads(dex):
    """[(descriptor, superclass descriptor or None, class_data_off)] of every class_def of a dex, the headers only
    (cached on the Dex). Raises on a structure it cannot read."""
    got = getattr(dex, "_kb2_heads", None)
    if got is not None:
        return got
    out = []
    for c in range(dex.cls_size):
        o = dex.cls_off + c * 32
        sup_i = dex._u4(o + 8)
        out.append((dex.type_str(dex._u4(o)), dex.type_str(sup_i) if sup_i != NO_INDEX else None, dex._u4(o + 24)))
    try:
        dex._kb2_heads = out
    except Exception:
        pass
    return out


def _class_methods(dex, data_off):
    """[(method index, access flags, code_off)] of one class_data item (direct, then virtual methods)."""
    out = []
    if not data_off:
        return out
    d = dex.d
    p = data_off
    sf, p = _uleb(d, p)
    inf, p = _uleb(d, p)
    dm, p = _uleb(d, p)
    vm, p = _uleb(d, p)
    for _ in range(sf + inf):
        _, p = _uleb(d, p)
        _, p = _uleb(d, p)
    for cnt in (dm, vm):
        mi = 0
        for _ in range(cnt):
            di, p = _uleb(d, p)
            mi += di
            fl, p = _uleb(d, p)
            co, p = _uleb(d, p)
            out.append((mi, fl, co))
    return out


class _DexView:
    """The id tables of one dex (strings, types, protos, methods, class_defs) read on demand: what ART's class
    linker reads to resolve a call, without the code items the VM's Dex indexes up front (review of e281f95: a
    6 MB secondary dex of 54,000 methods cost 0.36 s a set when it was parsed whole for every bundle). Shared by
    content for the process (_view)."""

    def __init__(self, data):
        self.d = data
        u4 = self._u4
        self.str_size, self.str_off = u4(56), u4(60)
        self.type_size, self.type_off = u4(64), u4(68)
        self.proto_size, self.proto_off = u4(72), u4(76)
        self.meth_size, self.meth_off = u4(88), u4(92)
        self.cls_size, self.cls_off = u4(96), u4(100)
        self._str_cache = {}

    def _u2(self, o):
        return struct.unpack_from("<H", self.d, o)[0]

    def _u4(self, o):
        return struct.unpack_from("<I", self.d, o)[0]

    def string(self, i):
        c = self._str_cache.get(i)
        if c is not None:
            return c
        off = self._u4(self.str_off + i * 4)
        _, p = _uleb(self.d, off)
        end = self.d.index(b"\x00", p)
        s = self.d[p:end].decode("utf-8", "replace")            # as the VM's Dex decodes it
        self._str_cache[i] = s
        return s

    def type_str(self, i):
        return self.string(self._u4(self.type_off + i * 4))

    def meth(self, i):
        o = self.meth_off + i * 8
        return self.type_str(self._u2(o)), self.string(self._u4(o + 4))


def _view(data, h):
    got = _VIEWS.get(h)
    if got is None:
        got = _put(_VIEWS, h, _DexView(data), 8)
    return got


def _dex_order(m):
    """The place of a classes*.dex member in the class loader's path: classes.dex 1, classesN.dex N (N >= 2)."""
    digits = m.group(1)
    if not digits:
        return 1
    if digits.startswith("0") or int(digits) < 2:
        return _ODD
    return int(digits)


class _Method:
    __slots__ = ("cls", "name", "sig", "flags", "code", "midx", "dex", "main")

    def __init__(self, cls, name, sig, flags, code, midx, dex, main):
        self.cls, self.name, self.sig, self.flags, self.code, self.midx, self.dex, self.main = \
            cls, name, sig, flags, code, midx, dex, main


class _Package:
    """Every dex member of the delivery, indexed the way ART's class linker resolves a method: by class
    descriptor, then (name, signature) up the superclass chain. `main` marks the members the app's own class
    loader loads (classes.dex, classes2.dex, ...; `order` is their place in its path); a dex an app loads itself
    (assets/payload.dex) is not one. Only the class headers are read up front; a class's methods are read when a
    resolution or the load phase needs them, so a large dex costs little more than the classes a call touches."""

    def __init__(self, members, dex):
        self.defs = {}               # descriptor -> [(dex, descriptor, superclass, class_data_off, main, order)]
        self.broken = False
        self._tables = {}
        self._subs = {}
        # One dex is often listed twice (the runner's files hold `<delivery> -> classes.dex` beside `classes.dex`):
        # a member is its CONTENT, read once, and it is the class loader's own when any of its names, read after
        # the container arrow, is classes.dex, classes2.dex, ...
        unique = {}
        for name, data in members:
            data = bytes(data)
            ent = unique.setdefault(_digest(data), [data, False, _ODD])
            m = _LAUNCHER.fullmatch(str(name).rsplit(" -> ", 1)[-1])
            if m:
                ent[1] = True
                ent[2] = min(ent[2], _dex_order(m))
        # KB-2 fix round 2 (review of 4250749, hardening 5): the class loader opens classes.dex, classes2.dex, ... and
        # stops at the first number missing, so a classesN.dex after a gap (or classes1.dex) is never the app's own
        orders = {ent[2] for ent in unique.values() if ent[1] and ent[2] < _ODD}
        run = 0
        while run + 1 in orders:
            run += 1
        for ent in unique.values():
            if ent[1] and ent[2] > run:
                ent[1], ent[2] = False, _ODD
        try:
            cur = _digest(bytes(dex.d))
        except Exception:
            cur = None
        for h, (data, main, order) in unique.items():
            try:
                dx = dex if h == cur else _view(data, h)
                for (desc, sup, off) in _class_heads(dx):
                    self.defs.setdefault(desc, []).append((dx, desc, sup, off, main, order))
            except Exception:
                self.broken = True
        if not unique:
            self.broken = True
        self.key = tuple(sorted((h, main) for h, (_d, main, _o) in unique.items()))

    def _table(self, ent):
        """{(name, signature): _Method} of one class definition, None marking a key it lists twice (no dex ART
        loads does that): resolve() then calls the method ambiguous. Read once."""
        dx, desc, _sup, off, main, _order = ent
        key = (id(dx), desc, off)
        table = self._tables.get(key)
        if table is None:
            table = {}
            for (mi, fl, co) in _class_methods(dx, off):
                _mcls, mname = dx.meth(mi)
                k = (mname, _sig(proto(dx, mi)))
                table[k] = None if k in table else _Method(desc, mname, k[1], fl, bool(co), mi, dx, main)
            self._tables[key] = table
        return table

    def jni_facts(self):
        """(classes, natives) for the load phase: the internal names (a/b/C) of every class the app's class
        loader defines (what FindClass may answer) and the (class, name, signature) of every ACC_NATIVE method
        those classes declare with a readable signature (what RegisterNatives may bind). Cached by content."""
        got = _FACTS.get(self.key)
        if got is not None:
            return got
        classes, natives = set(), set()
        for desc, defs in self.defs.items():
            if not (desc.startswith("L") and desc.endswith(";")):
                continue
            for (dx, _d, _sup, off, main, _order) in defs:
                if not main:
                    continue
                classes.add(desc[1:-1])
                for (mi, fl, _co) in _class_methods(dx, off):
                    if fl & ACC_NATIVE:
                        sig = _sig(proto(dx, mi))
                        if sig is not None:
                            natives.add((desc[1:-1], dx.meth(mi)[1], sig))
        return _put(_FACTS, self.key, (frozenset(classes), frozenset(natives)), 8)

    def declares_native(self, name):
        for defs in self.defs.values():
            for (dx, _d, _sup, off, _main, _order) in defs:
                for (mi, fl, _co) in _class_methods(dx, off):
                    if fl & ACC_NATIVE and dx.meth(mi)[1] == name:
                        return True
        return False

    def _is_sub(self, desc, base):
        """True when `desc`'s superclass chain, through classes the delivery defines, reaches `base`."""
        key = (desc, base)
        got = self._subs.get(key)
        if got is None:
            got, cur, seen = False, desc, set()
            while cur is not None and cur not in seen and len(seen) <= 64:
                seen.add(cur)
                defs = self.defs.get(cur)
                if not defs:
                    break
                sups = {ent[2] for ent in defs}
                if base in sups:
                    got = True
                    break
                if len(sups) != 1:
                    got = True                  # two definitions disagree on the superclass: count it (strict)
                    break
                cur = next(iter(sups))
            self._subs[key] = got
        return got

    def _choose(self, defs, name, sig):
        """(definition, flag) of a class for a call of `name`/`sig`: the one definition; or, for a class the
        delivery defines more than once, the class loader's (its first main dex member) with no flag when every
        definition agrees on the superclass and on the method (flags, code), FLAG_DUP when they differ; or
        (None, reason) when the class loader's choice is not known."""
        if len(defs) == 1:
            return defs[0], None
        views = set()
        for ent in defs:
            hits = tuple(sorted(((mname, msig, None if m is None else (m.flags & (ACC_NATIVE | ACC_STATIC), m.code))
                                 for (mname, msig), m in self._table(ent).items()
                                 if mname == name and (sig is None or msig is None or msig == sig)), key=repr))
            views.add((ent[2], hits))
        mains = sorted((ent for ent in defs if ent[4]), key=lambda e: e[5])
        first = mains[0] if mains else None
        if len(views) == 1:
            return (first or defs[0]), None
        if first is None or first[5] >= _ODD or (len(mains) > 1 and mains[1][5] == first[5]):
            return None, "class %s is defined more than once in the delivery and the definitions differ" % \
                defs[0][1][:80]
        return first, FLAG_DUP

    def resolve(self, dex, midx, op):
        """('native' | 'java', _Method, flags), ('ambiguous', reason, ()) or (None, None, ()) for a method the
        delivery does not define (a framework method). `flags` holds FLAG_DUP when a class on the way was
        defined twice with differing definitions."""
        try:
            cls, name = dex.meth(midx)
        except Exception:
            return "ambiguous", "the method reference cannot be read", frozenset()
        sig = _sig(proto(dex, midx))
        cur, seen, found, flags = cls, set(), None, set()
        while cur is not None:
            if cur in seen or len(seen) > 64:
                return "ambiguous", "a superclass cycle", frozenset()
            seen.add(cur)
            defs = self.defs.get(cur)
            if not defs:
                return None, None, frozenset()
            ent, flag = self._choose(defs, name, sig)
            if ent is None:
                return "ambiguous", flag, frozenset()
            if flag:
                flags.add(flag)
            table = self._table(ent)
            hits = [m for (mname, msig), m in table.items()
                    if mname == name and (sig is None or msig is None or msig == sig)]
            if len(hits) > 1 or None in hits:
                return "ambiguous", "%s.%s matches more than one method" % (cur[:80], name[:40]), frozenset()
            if hits:
                found = hits[0]
                break
            cur = ent[2]
        if found is None:
            return None, None, frozenset()
        if op in VIRTUAL_OPS:
            # virtual dispatch: an override in a subclass the delivery defines may be what a device runs
            for desc, defs in self.defs.items():
                if desc == found.cls or not self._is_sub(desc, found.cls):
                    continue
                for ent in defs:
                    for (mname, msig), m in self._table(ent).items():
                        if mname == name and (found.sig is None or msig is None or msig == found.sig) and \
                                (m is None or m.flags & ACC_NATIVE or found.flags & ACC_NATIVE):
                            return "ambiguous", "%s.%s is also defined by %s (virtual dispatch)" % (
                                found.cls[:80], name[:40], desc[:80]), frozenset()
        if found.flags & ACC_NATIVE and bool(found.flags & ACC_STATIC) != (op in STATIC_OPS):
            return "ambiguous", "a static/instance mismatch (IncompatibleClassChangeError on a device)", frozenset()
        return ("native" if found.flags & ACC_NATIVE else "java"), found, frozenset(flags)


class Target:
    """How ART binds one call: `calls` [(image, exported symbol or None, vaddr or None)] (every emulable library
    that would bind it), `call_bodies` (per call, the key of its legacy-readable body or None), `bodies`
    {key: (symbol, (e_machine, code), aarch64 code or None)} (the distinct exported bodies the legacy reader can
    read, from emulable and from other ELF64 libraries), `extra` (keys of bodies only the legacy reader can read:
    a library this engine does not load), `how` ('registered', 'exported', or 'framework': a method the delivery
    does not define, run as the framework's), `flags` (demotions), `image_ok` (False: the whole image is not
    asked) and `decline` (a reason nothing about the call can be proven)."""
    __slots__ = ("calls", "call_bodies", "bodies", "extra", "how", "pr", "decline", "flags", "image_ok", "ident",
                 "unasked", "abi32_only")

    def __init__(self, calls=(), how="exported", pr=None, decline=None, call_bodies=(), bodies=None, extra=(),
                 flags=frozenset(), image_ok=True, unasked=frozenset(), abi32_only=False):
        self.calls, self.how, self.pr, self.decline = list(calls), how, pr, decline
        self.call_bodies, self.bodies, self.extra = list(call_bodies), dict(bodies or {}), list(extra)
        self.flags, self.image_ok = frozenset(flags), image_ok
        self.unasked = frozenset(unasked)   # why the whole image is not asked: 'load' (flagged), 'size', 'problem'
        # +abi-unverified came only from 32-bit (ELF32) libraries holding the name, with no JNI_OnLoad of theirs: the
        # 32-bit legs so-ambig's SO_ELF32_LEGS="ignore" lets the 64-bit binding answer for (fix round 3, item 3)
        self.abi32_only = bool(abi32_only)
        self.ident = tuple((id(img), sym, entry) for img, sym, entry in self.calls)


def _declined(why, pr=None):
    return Target(pr=pr, decline=why)


# --------------------------------------------------------------------------------------- the bundle
class Bundle:
    """The native libraries of one delivery (each once, by content; parsed only when a call could bind to it),
    the delivery's dex members (the package ART resolves against), a per-call target cache, a memo of
    whole-image evaluations and the delivery's work budgets."""

    def __init__(self, so_members, package=()):
        self.raws = []                          # [(sha1, bytes)] in the delivery's order
        self.loadable = False
        self.targets = {}
        self.memo = {}
        self.blocks = TOTAL_BLOCKS
        self.mem = TOTAL_MEM
        self.calls_left = MAX_IMAGE_CALLS
        self.setup_left = TOTAL_SETUP_BYTES
        self.load_blocks = TOTAL_LOAD_BLOCKS
        self.load_mem = TOTAL_LOAD_MEM
        self.loads_left = MAX_LOAD_PHASES
        self.members = list(package or ())
        self.package = None
        self.table = None                       # the delivery's merged native table (what the loose match reads)
        self._img = {}                          # sha1 -> ElfImage, or the EmulationError of its load
        self._load = {}                         # sha1 -> (registered map, error or None)
        # dex_chain_codec's _SoBodies (so-ambig fix round 1: each distinct body read once): its tables are reused
        self._so_bodies = so_members if callable(getattr(so_members, "body", None)) else None
        if not available():
            return
        seen = set()
        for b in so_members or ():
            b = bytes(b)
            h = _digest(b)
            if h in seen:                       # one library listed twice (`<delivery> -> lib/...` and `lib/...`)
                continue
            seen.add(h)
            self.raws.append((h, b))
            if _elf64_machine(b) in _LOADABLE:
                self.loadable = True

    def __bool__(self):
        return self.loadable

    def _pkg(self, dex):
        if self.package is None:
            self.package = _Package(self.members or [("classes.dex", dex.d)], dex)
        return self.package

    def _image(self, h, raw):
        got = self._img.get(h)
        if got is None:
            try:
                got = _ni.load(raw)
            except Exception as e:
                got = e if isinstance(e, _ni.EmulationError) else _ni.EmulationError("%s: %s" % (type(e).__name__, e))
            self._img[h] = got
        return got

    def _load_of(self, h, img, dex):
        """(registered map, None) of one image's load phase (its constructors and JNI_OnLoad run against the
        delivery's classes and natives, native_image.load_info), or ({}, error) when it cannot be modelled: past
        the size bounds, past the delivery's load-phase budget, or something the model does not run. Once per
        delivery; computed once per process (charged to every delivery as when it was computed)."""
        got = self._load.get(h)
        if got is not None:
            return got
        if not img.has_load_code(jni=True):
            got = ({}, None)
        elif _too_big(img):
            got = ({}, _ni.SetupError("the library is too large for the bounded whole-image path"))
        elif self.loads_left <= 0 or self.load_blocks <= 0 or self.load_mem <= 0:
            got = ({}, _ni.SetupError("the delivery's load-phase budget is spent"))
        elif 2 * (img.hi - img.lo) > self.setup_left:
            # KB-2 fix round 2 (the review of 4250749, perf): a load phase maps the library's whole span in each of its
            # two runs; it is charged to the delivery's budget of image bytes like a call's runs (it was free: eight
            # JNI_OnLoad libraries with a 15 MiB .bss each beside the binding one cost 0.17 s a delivery)
            got = ({}, _ni.SetupError("the delivery's load-phase budget of image bytes is spent"))
        else:
            self.setup_left -= 2 * (img.hi - img.lo)
            classes, natives = self._pkg(dex).jni_facts()
            # both runs share what the delivery's load-phase budget has left (the second run gets what the first left)
            key = (h, classes, natives, self.load_blocks, self.load_mem)
            hit = _LOADS.get(key)
            if hit is None:
                usage = {}
                try:
                    info = _ni.load_info(img, classes, natives, max_blocks=PER_RUN_BLOCKS, max_mem=PER_RUN_MEM,
                                         usage=usage, total_blocks=self.load_blocks, total_mem=self.load_mem)
                    hit = (dict(info["registered"]), None)
                except _ni.EmulationError as e:
                    hit = ({}, (type(e), str(e)))
                except Exception as e:
                    hit = ({}, (_ni.EmulationError, "%s: %s" % (type(e).__name__, e)))
                hit = _put(_LOADS, key, hit + (usage.get("blocks", 0), usage.get("mem", 0)), 256)
            self.loads_left -= 1
            self.load_blocks -= hit[2]
            self.load_mem -= hit[3]
            got = (dict(hit[0]), None if hit[1] is None else hit[1][0](hit[1][1]))
        self._load[h] = got
        return got

    # ------------------------------------------------------------ legacy bodies
    def _bodies_of(self, h, raw, mod):
        """The legacy reader's own symbol table of ONE library ({symbol: (e_machine, code)}, `_parse_so`): the one
        dex_chain_codec's _SoBodies already read for the delivery when there is one (the port onto so-ambig: each
        distinct body is parsed once a delivery), else read here."""
        body = None
        if self._so_bodies is not None:
            try:
                body = self._so_bodies.body(raw)
            except Exception:
                body = None
        if body is not None:
            try:
                return body.funcs               # read-only here (callers only look a symbol up)
            except Exception:
                pass
        got = _BODIES.get(h)
        if got is None:
            try:
                got = dict(mod._parse_so(raw)) if mod is not None and hasattr(mod, "_parse_so") else {}
            except Exception:
                got = {}
            _put(_BODIES, h, got, 16)
        return got

    def _arm_of(self, h, raw, mod):
        got = _ARMS.get(h)
        if got is None:
            got = {}
            na = getattr(mod, "native_arm64", None) if mod is not None else None
            if na is not None:
                try:
                    got = dict(na.aarch64_functions(raw))
                except Exception:
                    got = {}
            _put(_ARMS, h, got, 16)
        return got

    def _body(self, h, raw, sym, mod):
        ent = self._bodies_of(h, raw, mod).get(sym)
        if not (isinstance(ent, tuple) and len(ent) == 2 and isinstance(ent[1], (bytes, bytearray))):
            return None, None
        return (ent[0], bytes(ent[1])), self._arm_of(h, raw, mod).get(sym)

    # ------------------------------------------------------------ targets
    def target(self, vm, op, midx):
        """The Target of a call, else None (the shipped reader's own path decides, as before: a framework
        method no app export is named like, or an app method no native export could bind). Cached per
        (dex, method, op kind)."""
        dex = vm.dex
        if self.table is None:
            self.table = vm.native_syms if isinstance(vm.native_syms, dict) else {}
        key = (id(dex), midx, op in STATIC_OPS, op in VIRTUAL_OPS)
        if key in self.targets:
            return self.targets[key]
        try:
            t = self._target(vm, dex, op, midx)
        except Exception as e:
            t = _declined("the binding could not be read (%s)" % str(e)[:120])
        self.targets[key] = t
        return t

    def _target(self, vm, dex, op, midx):
        mod = sys.modules.get(type(vm).__module__)
        pkg = self._pkg(dex)
        kind, m, rflags = pkg.resolve(dex, midx, op)
        if kind != "native":
            loose = _legacy_would_bind(self.table, dex, midx)
            if kind == "ambiguous" and (loose or pkg.declares_native(dex.meth(midx)[1])):
                return _declined(m)
            if kind is None and loose is not None:
                # a method the delivery does not define is the framework's on a device (Long.valueOf beside an app
                # export Java_..._Codec_valueOf): run as the framework model, with no native table to bind
                return Target(how="framework")
            if loose is not None:
                # a method the delivery defines without declaring it native runs its own code on a device: the
                # shipped reader's loose name match would bind the export `loose`
                return _declined("%s is not a native the delivery declares, yet the shipped reader's name match "
                                 "would bind %s" % (dex.meth(midx)[1][:40], loose[:120]))
            return None
        if not m.main:
            return _declined("a native declared in a dex the app's class loader does not load")
        pr = proto(m.dex, m.midx)
        names = jni_names(m.cls, m.name, pr[1] if pr else None)
        if not names:
            return _declined("the declaring class has no JNI name", pr)
        short, long_ = names
        needles = [s.encode("utf-8", "surrogatepass") + b"\x00" for s in (short, long_) if s]
        rkey = (m.cls[1:-1], m.name, m.sig) if m.sig else None
        flags = set(rflags)
        # Every library that holds the call's JNI name or a JNI_OnLoad is a candidate binding (ABI variants are
        # alternatives a device chooses between, and they must agree): a library whose JNI_OnLoad registered the
        # method binds THAT function (RegisterNatives wins over dlsym); otherwise ART's dlsym of the short name,
        # then the long name, of the library's exports. A library that holds neither can bind nothing here: it is
        # not parsed, and its constructors are not run.
        calls, call_bodies, bodies, registered, extra = [], [], {}, False, []
        image_ok = True
        unasked = set()
        abi32, abi_other = False, False          # where +abi-unverified came from (fix round 3, item 3)
        for (h, raw) in self.raws:
            has_name = any(_holds(h, raw, nd) for nd in needles)
            has_onload = _holds(h, raw, b"JNI_OnLoad\x00")
            # a library that imports JNI_GetCreatedJavaVMs can reach a JNIEnv from a constructor and register
            # natives without a JNI_OnLoad: its load phase is read as a JNI_OnLoad's is
            seeks_vm = _holds(h, raw, b"JNI_GetCreatedJavaVMs\x00")
            if not (has_name or has_onload or seeks_vm):
                continue
            if not has_name and len(raw) > MAX_IMAGE_BYTES and _elf64_machine(raw) in _LOADABLE and \
                    not _device_refuses(raw):
                # a large library (a game engine's, a framework's) that could bind the call only through its load
                # phase: that phase is past the bounds the whole image runs anyway, so it is not parsed for it
                flags.add(FLAG_ONLOAD + "@size")
                continue
            img = self._image(h, raw)
            if isinstance(img, Exception):
                # a library this engine does not load: the legacy reader alone may read an ELF64 body of it. One a
                # device may load (past this engine's bounds: over 32 MiB, over 200,000 relocations, a W+X segment
                # Android before 8.0 accepts) has neither its export's address nor its load phase checked here:
                # demoted. One no loader accepts at all (no program headers, no PT_LOAD) is read as before this
                # build; one of another machine or class (32-bit ARM) runs on a device of that ABI only
                # (+abi-unverified)
                loadable = _elf64_machine(raw) in _LOADABLE
                refused = loadable and _device_refuses(raw)
                if has_name:
                    hit = [s for s in (short, long_) if s and _holds(h, raw, s.encode("utf-8", "surrogatepass") + b"\x00")]
                    body, arm = self._body(h, raw, hit[0], mod)
                    if body is not None and body[0] in _LOADABLE:
                        # (the shipped reader is handed the body under the SHORT name, the one its name match binds:
                        # KB-2 fix round 2, the review of 4250749, minor; see the exported case below)
                        bodies.setdefault(body, (short, body, arm))
                        extra.append(body)
                        if not refused:
                            flags.add(FLAG_LIB)
                    else:
                        flags.add(FLAG_ABI)          # nothing here reads it (32-bit ARM, another machine)
                        if raw[:5] == b"\x7fELF\x01" and not (has_onload or seeks_vm):
                            abi32 = True             # a 32-bit leg holding the name, no load-time code of its own
                        else:
                            abi_other = True
                if (has_onload or seeks_vm) and not refused:
                    flags.add(FLAG_ONLOAD + "@unloadable" if loadable else FLAG_ABI)
                    if not loadable:
                        abi_other = True
                continue
            ex = img.exports()
            onload = "JNI_OnLoad" in ex or seeks_vm
            sym = short if short in ex else (long_ if long_ and long_ in ex else None)
            if sym is None and not onload:
                continue
            regs, err = self._load_of(h, img, dex)
            if err is not None and onload:
                # what it registers is unknown: the bindings read here stand, demoted, under a key that names why
                flags.add(FLAG_ONLOAD + "@" + _reason_tag(err))
            if rkey is not None and rkey in regs:
                calls.append((img, None, regs[rkey]))
                call_bodies.append(None)
                registered = True
                continue
            if sym is None:
                continue
            if sym in img.ambiguous_exports():
                return _declined("one library defines %s twice" % sym[:120], pr)
            calls.append((img, sym, None))
            body, arm = self._body(h, img.data, sym, mod)
            # the legacy reader's table merges .dynsym and .symtab by name: its body must be the bytes at the
            # address the dynamic export (what dlsym returns) names, else it is not a reading of that function
            body = body if body is not None and _at(img, ex[sym], body[1]) else None
            arm = arm if arm is not None and _at(img, ex[sym], arm) else None
            bkey = None
            if body is not None and body[0] in _LOADABLE:
                bkey = body
                # KB-2 fix round 2 (the review of 4250749, minor): the shipped reader is handed this body under the
                # method's SHORT JNI name, the one its name match binds. Asked about the LONG (overloaded) name it bound
                # nothing and fell through to a framework model by class name (an app class named ...HexLong ran
                # Long.toHexString), and that model's value was taken as the native's reading; under the short name it
                # reads exactly this body, the function ART binds when no short name is exported
                bodies.setdefault(bkey, (short, body, arm))
            call_bodies.append(bkey)
            if err is not None:
                image_ok = False                     # a call runs the load phase first: the image cannot run it
                unasked.add("load")
                if not onload:
                    flags.add(FLAG_CTOR)
            if _too_big(img):
                image_ok = False
                unasked.add("size")
            if img.problem:
                image_ok = False                     # every run of it is refused (SetupError): say why, never plain
                unasked.add("problem")
        if registered:
            if FLAG_CTOR in flags or extra:
                return _declined("a RegisterNatives binding beside a library whose binding cannot be read", pr)
            # KB-2 port onto so-ambig (two .so bodies of one machine binding one JNI method are None, x17's principle):
            # with a RegisterNatives binding, two different libraries of one machine that bind the method (the one that
            # registers it and another that registers or exports it) leave the binding to which library a device loads,
            # which the bytes do not say. Two architectures stay alternatives a device chooses by its ABI (all must agree)
            per = {}
            for img, _s, _e in calls:
                per.setdefault(img.machine, set()).add(_img_digest(img))
            if any(len(v) > 1 for v in per.values()):
                return _declined("two libraries of one machine bind %s.%s, one by RegisterNatives (so-ambig: which "
                                 "library a device loads is not in the bytes)" % (m.cls[:80], m.name[:40]), pr)
            return Target(calls, "registered", pr, call_bodies=call_bodies, flags=flags, image_ok=image_ok,
                          unasked=unasked)
        if not calls and not extra:
            return _declined("no library registers or exports %s.%s (UnsatisfiedLinkError)" % (m.cls[:80],
                                                                                              m.name[:40]), pr)
        # the port onto so-ambig (x17's principle, which so-ambig's loose binding key cannot see for a long name): two
        # different bodies of one machine exporting the method's exact JNI name decline even when they compute alike
        # (which library a device loads is not in the bytes); one body in two libraries is one definition, as there
        bym = {}
        for (img, sym, _e), bkey in zip(calls, call_bodies):
            bym.setdefault(img.machine, set()).add(bkey if bkey is not None else ("image", _img_digest(img), sym))
        for bkey in extra:
            bym.setdefault(bkey[0], set()).add(bkey)
        if any(len(v) > 1 for v in bym.values()):
            return _declined("two .so bodies of one machine export %s.%s (so-ambig: which library a device loads is not "
                             "in the bytes)" % (m.cls[:80], m.name[:40]), pr)
        return Target(calls, "exported", pr, call_bodies=call_bodies, bodies=bodies, extra=extra, flags=flags,
                      image_ok=image_ok and bool(calls), unasked=unasked, abi32_only=abi32 and not abi_other)


def _at(img, vaddr, code):
    """True when `code` is the file-backed bytes at image address `vaddr`."""
    try:
        return bool(code) and img.file_bytes(vaddr, len(code)) == bytes(code)
    except Exception:
        return False


def _legacy_would_bind(table, dex, midx):
    """The symbol the shipped reader's loose name match would bind to this call (over the delivery's merged
    native table), or None."""
    try:
        cls, name = dex.mname.get(midx, dex.meth(midx))
        want = "_" + name
        for sym in list(table or ()):
            if isinstance(sym, str) and sym.endswith(want) and \
                    ("native" in cls.lower() or "jni" in sym.lower() or sym.startswith("Java_")):
                return sym
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------------------- value mapping
_PRIM = {"Z", "B", "S", "C", "I", "J", "F", "D"}
_NARROW = ("I", "S", "B", "C", "Z")
_NO = object()


def _ret_kind(pr, shorty_ret):
    if pr is None:
        return shorty_ret if shorty_ret in _PRIM or shorty_ret == "V" else "?"
    r = pr[0]
    if r in _PRIM or r == "V":
        return r
    if r == "Ljava/lang/String;":
        return "str"
    if r == "[B":
        return "arr:B"
    if r == "[I":
        return "arr:I"
    if r.startswith("["):
        return "arr:?"
    return "obj"


def _java_args(vm, midx, args, pr, static, mod):
    """[(kind, value)] for native_image.call_jni from the Dalvik argument registers, or None to decline.
    A boxed scalar is unboxed only for a PRIMITIVE parameter: passed to a reference parameter it is an object
    (review of e281f95: a boxed Long 0 reached the native as NULL, where a device passes a non-NULL jobject)."""
    shorty = vm.dex.meth_shorty(midx)
    if not shorty:
        return None
    params = list(shorty[1:])
    descs = pr[1] if pr else [None] * len(params)
    ai = 0 if static else 1
    out = []
    for p, desc in zip(params, descs):
        v = args[ai] if ai < len(args) else None
        if p in ("F", "D"):
            # B-241: a jfloat / jdouble travels as its IEEE bit pattern, which is how a Dalvik register holds it
            if isinstance(v, mod._Box):
                v = v.v
            if not isinstance(v, int) or isinstance(v, bool):
                return None
            out.append((p, v & (0xFFFFFFFF if p == "F" else M64)))
        elif p in _PRIM:
            if isinstance(v, mod._Box):
                v = v.v
            if not isinstance(v, int) or isinstance(v, bool):
                return None
            out.append((p, v))
        else:
            if isinstance(v, mod._Str):
                v = v.val
            if v is None or (type(v) is int and v == 0):
                out.append(("obj", None))                # Dalvik's null (const/4 vN, 0 leaves the integer 0)
            elif isinstance(v, mod._Box):
                out.append(("obj", v))                   # Integer.valueOf(0) and the like: a non-NULL object
            elif isinstance(v, int):
                return None                              # an integer where a reference is expected: not modelled
            elif isinstance(v, str):
                out.append(("str", v))
            elif isinstance(v, list):
                kind = "arr:?"
                if desc == "[B":
                    kind = "arr:B"
                elif desc == "[I":
                    kind = "arr:I"
                out.append((kind, v))
            else:
                out.append(("obj", v))
        ai += 2 if p in ("J", "D") else 1
    return out


def _legacy_view(ret, v1):
    """The legacy reader's raw register value seen through the method's return type."""
    if not isinstance(v1, int):
        return None
    if ret == "J":
        return v1 & M64
    if ret in _NARROW:
        try:
            return _ni._narrow(ret, v1)
        except Exception:
            return None
    return None


def _vm_value(ret, v1):
    """The legacy reading as the VM keeps a value of the method's return type: a jint/jshort/jbyte signed, a
    jchar and a jboolean unsigned (review of e281f95: a negative jint handed over as its raw zero-extended register
    took the wrong leg of an if-ltz); _NO when it does not fit (a jboolean outside 0/1)."""
    if not isinstance(v1, int) or isinstance(v1, bool):
        return v1
    if ret == "J":
        return v1 & M64
    if ret in _NARROW:
        got = _legacy_view(ret, v1)
        return _NO if got is None else got
    return v1


def _body_shape(v):
    """True for the shipped native table's value shape, (e_machine, code bytes)."""
    return isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], int) and isinstance(v[1], (bytes, bytearray))


def _legacy_read(vm, legacy, op, midx, args, sym, ent, arm):
    """The shipped reader's reading of exactly one body: it is handed a native symbol table that holds only
    `sym` (with `ent` = (e_machine, code) of the one library read), so its own name match can bind nothing
    else. (ok, value, error)."""
    saved = vm.native_syms
    saved_arm = getattr(vm, "native_arm", None)
    vm.native_syms = {sym: ent}
    if saved_arm is not None:
        vm.native_arm = {sym: arm} if arm is not None else {}
    try:
        return True, legacy(op, midx, args), None
    except Exception as e:           # any failure of the legacy reader is its decline
        return False, None, e
    finally:
        vm.native_syms = saved
        if saved_arm is not None:
            vm.native_arm = saved_arm


def _framework(vm, legacy, op, midx, args):
    """A method the delivery does not define, run as the framework's: the shipped reader with an empty native
    table, so its loose name match cannot bind an app export to it."""
    saved = vm.native_syms
    saved_arm = getattr(vm, "native_arm", None)
    vm.native_syms = {}
    if saved_arm is not None:
        vm.native_arm = {}
    try:
        return legacy(op, midx, args)
    finally:
        vm.native_syms = saved
        if saved_arm is not None:
            vm.native_arm = saved_arm


def _mark(vm, flags):
    if flags:
        vm._kb2_flags = frozenset(getattr(vm, "_kb2_flags", frozenset())) | frozenset(flags)


# --------------------------------------------------------------------------------------- the hook
_BOOT = ("Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Llibcore/", "Lsun/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/",
         "Lorg/xmlpull/", "[")        # dex_chain_codec._BOOT_PREFIXES (used when the VM's module does not say)


def _is_boot(vm, cls):
    mod = sys.modules.get(type(vm).__module__)
    fn = getattr(mod, "_boot_class", None) if mod is not None else None
    if callable(fn):
        try:
            return bool(fn(cls))
        except Exception:
            pass
    return isinstance(cls, str) and cls.startswith(_BOOT)


def _gate(vm, midx, t, sa, legacy_bodies, image_only, decline, plain=True):
    """The KB-2 port onto so-ambig: the flags a reading of the bridge adds, or a decline. so-ambig's binding rules
    (dex_chain_codec._so_verdict, over the delivery's whole native table) and the bridge's own must BOTH allow a reading;
    where they disagree the call declines or the reading is unsure (each rule here only restricts):
      sa None   (so-ambig binds no native): a boot class's method is never one of the app's natives (decline); otherwise
                a reading of the whole image alone stands (a RegisterNatives binding, a long name: unsure anyway), and a
                body the shipped reader read (a long-name export, handed it under the short name) only unsure under
                `+jni-long`
      "hard"    (two .so bodies of one machine, an exact-name conflict, an export no loader returns, an opaque body, a
                JNI_OnLoad not proven inert, DT_INIT / DT_INIT_ARRAY, ...): decline, whatever the whole image read (its
                RegisterNatives binding included)
      "bind"    the bridge's binding must be the export so-ambig binds (never a RegisterNatives one), every body the
                legacy reader read one so-ambig binds, and every definition so-ambig binds read by the legacy reader (as
                its own path reads them: every architecture of an EM_MULTI symbol); a definition only the whole image read
                makes a plain reading `+native-image` (unsure).
    `plain` is False for a reading that is already unsure (a demotion, a new key): no flag is added to it then, since
    what this gate restricts is a PLAIN answer."""
    try:
        cls = vm.dex.meth(midx)[0]
    except Exception:
        cls = None
    if sa is None:
        if _is_boot(vm, cls):
            raise decline("native call not proven: %s is a boot class, never one of the app's natives (so-ambig), yet "
                          "the bridge binds its method" % str(cls)[:80])
        if image_only or not plain:
            return set()
        # no symbol the loose rule matches, yet the shipped reader read a body (handed it under the short name): a
        # native exported under its LONG (overloaded) name only, which so-ambig's rules never bind. Both engines read
        # it, but no plain answer stands where so-ambig binds nothing: a key of its own, unsure until judged
        return {FLAG_LONG}
    if sa[0] != "bind":
        raise decline("native call not proven (so-ambig): %s" % str(sa[1])[:240])
    allowed = sa[1]
    if any(not isinstance(d, tuple) or d[0] not in _LOADABLE for d in allowed):
        # so-ambig's own path runs every architecture's body (_native_multi) and declines one no emulator models
        # (armeabi-v7a, RISC-V): which architecture's device the answer is computed on is not in the bytes
        raise decline("native call not proven (so-ambig): a body of a machine no emulator models binds it too")
    stray = [b for b in legacy_bodies if b not in allowed]
    if stray:
        raise decline("native call not proven: the bridge read %d body(ies) so-ambig does not bind" % len(stray))
    if t.how != "exported":
        raise decline("native call not proven: so-ambig binds an export, the bridge a RegisterNatives function")
    if image_only or not plain:
        return set()                                     # +native-image, or another demotion, already
    if not set(allowed) <= set(legacy_bodies):
        # so-ambig's own path reads every architecture's body (_native_multi); one only the whole image read is no
        # reading of that path: the code rests on the whole image there
        return {ROUTE_IMAGE}
    return set()


def _elf32_ignored(vm):
    """True when the VM's module (dex_chain_codec) lets the 64-bit binding answer beside a 32-bit leg
    (SO_ELF32_LEGS == "ignore")."""
    mod = sys.modules.get(type(vm).__module__)
    return getattr(mod, "SO_ELF32_LEGS", None) == "ignore"


def _load_unknown(flags):
    """True when a reading stands beside code a device runs before the call that the model did not run, or ran on
    another ABI (KB-2 fix round 3, the review of 18ab31d): a JNI_OnLoad it could not model (+onload-unverified@<why>;
    <why> names only the FIRST thing the model met, so a decoy with the same first import that then registers another
    function shares the key), constructors it could not run (+ctor-unverified), a library of another ABI holding the
    name or a JNI_OnLoad (+abi-unverified). Where so-ambig binds no symbol of the call, nothing else vouches for the
    binding, and such a reading declines."""
    return any(f == FLAG_CTOR or f == FLAG_ABI or f.startswith(FLAG_ONLOAD + "@") for f in flags)


def invoke(vm, op, midx, args, legacy, decline, verdict=None):
    """VM._invoke for a method without dex code when the delivery ships a library this engine might load.
    `verdict(midx)` is so-ambig's reading of the call (dex_chain_codec._so_verdict); see _gate."""
    bundle = vm.native_images
    sa_box = []

    def sa():
        if not sa_box:
            try:
                sa_box.append(verdict(midx) if verdict is not None else None)
            except Exception as e:      # no verdict: nothing so-ambig allows is known
                sa_box.append(("hard", "the so-ambig verdict raised %s" % type(e).__name__))
        return sa_box[0]
    if bundle and verdict is not None:
        # KB-2 fix round 3 (the review of 18ab31d, perf): so-ambig's verdict first. A call it declines declines here,
        # before the bridge parses a library or runs a load phase (eight JNI_OnLoads that spin cost 0.5 s a delivery
        # cold when the load phases ran first). Every path after would decline it as well: _gate, the framework
        # disagreement below, and the shipped reader's own binding when the bridge does not take the call.
        v = sa()
        if v is not None and v[0] != "bind":
            raise decline("native call not proven (so-ambig): %s" % str(v[1])[:240])
    t = bundle.target(vm, op, midx) if bundle else None
    if t is None:
        return legacy(op, midx, args)
    if t.how == "framework":
        if verdict is not None and sa() is not None:
            # the bridge runs the framework's method (the delivery does not define the class), while so-ambig's rules
            # bind (or decline) a native for it: the two readings disagree
            raise decline("native call not proven: the delivery does not define %s, which the bridge runs as the "
                          "framework's, and so-ambig's rules read a native for it" % str(vm.dex.meth(midx))[:120])
        return _framework(vm, legacy, op, midx, args)
    if t.decline is not None:
        # nothing about this call can be proven (no binding at all, an ambiguous resolution, a method that is no
        # native of the delivery): the legacy reading, which models none of it, is not taken
        raise decline("native call not proven: %s" % t.decline)
    pr = t.pr
    ret = _ret_kind(pr, (vm.dex.meth_shorty(midx) or "?")[0])
    leg = {}
    if t.how == "exported":                              # never for a RegisterNatives binding (it reads exports)
        for bkey, (sym, ent, arm) in t.bodies.items():
            # each body as itself: the shipped reader gets a one-entry table {sym: (e_machine, code)} of exactly this
            # library's body (so-ambig's table may hold EM_MULTI's definitions or EM_AMBIGUOUS's mark under sym; the
            # rules those stand for are _gate's)
            leg[bkey] = _legacy_read(vm, legacy, op, midx, args, sym, ent, arm)
    # outcome of the whole image: 'read' (a value), 'not asked' (a size bound, an image problem, an input it does not
    # model, a load phase it cannot model), 'unchecked' (it ran out of work, a delivery cap or budget stopped it, or this
    # module faulted) or 'failed' (it ran the call and could not finish it for any other reason)
    res, why, outcome = None, None, "not asked"
    if t.calls and t.image_ok:
        try:
            res = _run(vm, midx, args, pr, op, t, bundle, ret)
            outcome = "read"
        except _ni.SetupError as e:
            why = str(e)
        except _ni.BudgetError as e:
            why, outcome = str(e), "unchecked"
        except _ni.EmulationError as e:
            why, outcome = str(e), "failed"
        except Exception as e:           # a fault of this module is no reading, and no proof of another path
            why, outcome = "%s: %s" % (type(e).__name__, e), "unchecked"
    elif t.calls:
        why = "the whole image is not asked (%s)" % (", ".join(sorted(t.unasked)) or "a load phase it cannot model")
    oks = [(k, v) for k, (ok, v, _e) in leg.items() if ok]
    errs = [e for (ok, _v, e) in leg.values() if not ok and e is not None]
    if any("denied sentinel" in str(e) for e in errs):
        # the legacy reader READ a 0 (the gate-FAIL leg) and declined on it: that is a reading, not an absence of
        # one, so a whole image that reads anything else disagrees with it, and one that reads 0 is the sentinel
        raise decline("native call not proven: the legacy reader read the denied sentinel 0")
    # every library that binds the method must be read by one engine or the other
    uncovered = [i for i, bkey in enumerate(t.call_bodies) if res is None and not (bkey is not None and leg[bkey][0])]
    uncovered += [bkey for bkey in t.extra if not leg[bkey][0]]
    if uncovered:
        if not oks and res is None and errs:
            raise errs[0]
        raise decline("native call not proven: a library binding it is read by neither engine (%s)" %
                      (why or "the legacy reader declined"))
    if ret != "V" and len({(v & M64) if isinstance(v, int) else repr(v) for _k, v in oks}) > 1:
        raise decline("native call not proven: the libraries binding it disagree (legacy readings %r)"
                      % [v for _k, v in oks][:4])
    if oks:
        v1 = oks[0][1]
        if outcome == "failed":
            # a successful legacy run makes no call and reads no data: an image that ran the same function and
            # failed (an unmodelled import, an undefined read, the layouts disagreeing) followed another path, or
            # found an address dependence; review of e281f95: an emulator check on the legacy engine's fixed code
            # base gave its emulator leg plain
            raise decline("native call not proven: the whole image ran the call and could not finish it (%s), "
                          "where the legacy reader read %r: the two did not follow one path" % (why[:160], v1))
        if res is not None and not (res[0] == "void" and ret == "V") and \
                not (res[0] == "int" and _legacy_view(ret, v1) == res[1]):
            raise decline("native cross-check disagreement: legacy %r vs whole image %r" % (v1, res[1]))
        value = _vm_value(ret, v1)
        if value is _NO:
            raise decline("native call not proven: the legacy reading %r does not fit a %s return" % (v1, ret))
        unchecked = set()
        if t.calls and (outcome == "unchecked" or (outcome == "not asked" and not t.flags)):
            # KB-2 fix round 2 (the review of 4250749, item b): the whole image had a binding library to read and gave
            # no reading: out of work, past a delivery cap or budget (16 evaluations, image bytes, the work totals:
            # three heavy calls reached it), a library past the size bounds (9 MiB of zeros appended), an image problem
            # (DT_TEXTREL), an input it does not model. Its cross-check (an emulator check on the legacy engine's fixed
            # code base, a NULL JNIEnv) did not run, so the legacy reading is never plain: demoted, under a key that
            # names the method, so a name the judge accepts for one native never answers another. (A load phase it
            # cannot model carries its own demotion already, +ctor-unverified / +onload-unverified@<why>.)
            try:
                unchecked = {FLAG_UNCHECKED + "@" + _slug(vm.dex.meth(midx)[1], 32)}
            except Exception:
                unchecked = {FLAG_UNCHECKED + "@other"}
        flags = set(t.flags) | unchecked
        if FLAG_ABI in flags and t.abi32_only and verdict is not None and (sa() or ("",))[0] == "bind" and \
                _elf32_ignored(vm):
            # KB-2 fix round 3 (the review of 18ab31d, item 3): so-ambig binds the 64-bit export and, under its
            # SO_ELF32_LEGS "ignore" (the integrator's decision), lets it answer beside a 32-bit leg no emulator runs, as
            # af3dbf7 did; a 32-bit leg with a JNI_OnLoad or constructors is so-ambig's hard decline before this
            flags.discard(FLAG_ABI)
        if verdict is not None and sa() is None and _load_unknown(flags):
            raise decline("native call not proven: so-ambig binds no symbol of it, and a load phase the model could "
                          "not run (or a library of another ABI) may bind it: %s" % ", ".join(sorted(flags))[:160])
        if verdict is not None:
            flags |= _gate(vm, midx, t, sa(), [k for k, _v in oks], False, decline, plain=not flags)
        _mark(vm, flags)
        return value                                     # the legacy reading stands (agreed, alone, or demoted)
    if res is None:
        raise decline("native emulation declined (%s)" % (why or "no reading"))
    if res[0] == "null" or (res[0] in ("int", "float", "double") and res[1] == 0):
        # the whole image alone never assembles a code from the 0/NULL "denied" sentinel (the gate-FAIL leg);
        # B-241: a float or double whose bits are all zero (+0.0) is that sentinel too
        raise decline("native emulation declined (whole-image native returned the denied sentinel 0/NULL)")
    kind, value, arg_lists, commits, arr_obj = res
    flags = set(t.flags) | {ROUTE_CSTR if kind == "cstr" else ROUTE_IMAGE}
    if verdict is not None and sa() is None and _load_unknown(flags):
        raise decline("native call not proven: so-ambig binds no symbol of it, and a load phase the model could not "
                      "run (or a library of another ABI) may bind it: %s" % ", ".join(sorted(flags))[:160])
    if verdict is not None:
        flags |= _gate(vm, midx, t, sa(), [], True, decline, plain=False)
    for k, newvals in commits.items():                   # Java arrays the native changed, in place
        arg_lists[k][:] = newvals
    _mark(vm, flags)
    if kind == "arr" and arr_obj is not None:
        return arr_obj
    return value


def _freeze(v):
    return tuple(v) if isinstance(v, list) else v


def _jkey(jargs):
    # an opaque object is keyed by whether it is NULL only (no modelled JNI function reads its content or identity,
    # but a native may test it against NULL)
    return tuple((k, _freeze(v) if k != "obj" else v is None) for k, v in jargs)


def _run(vm, midx, args, pr, op, t, bundle, ret):
    mod = sys.modules.get(type(vm).__module__)     # the VM's own value classes (_Box, _Str)
    if mod is None or not hasattr(mod, "_Box") or not hasattr(mod, "_Str"):
        raise _ni.SetupError("the VM's value classes are not reachable")
    static = op in STATIC_OPS
    jargs = _java_args(vm, midx, args, pr, static, mod)
    if jargs is None:
        raise _ni.SetupError("argument kinds not modelled")
    key = (t.ident, _jkey(jargs), ret, static)
    hit = bundle.memo.get(key)
    if hit is None:
        hit = _evaluate(vm, t, jargs, ret, static, bundle)
        bundle.memo[key] = hit
    if isinstance(hit, Exception):
        raise type(hit)(str(hit))
    kind, value, commits, arr_arg = hit
    arg_lists = {k: jargs[k][1] for k in commits}
    arr_obj = None
    if kind == "arr":
        arr_obj = jargs[arr_arg][1] if arr_arg is not None else list(value)
        value = list(value)
    return (kind, value, arg_lists, {k: list(v) for k, v in commits.items()}, arr_obj)


def _evaluate(vm, t, jargs, ret, static, bundle):
    """One whole-image evaluation of a call (every binding library, both layouts each), within the delivery's
    budgets: (kind, value, {arg index: new elements}, returned argument index), or the EmulationError. Found in
    the process cache by content when an identical evaluation was computed at the same budget state, and charged
    to the delivery's budgets exactly as it was then."""
    # KB-2 fix round 2 (the review of 4250749, item b): a delivery cap or budget that stops the whole image is a
    # BudgetError (the call is 'unchecked': a legacy reading stands only demoted, +image-unchecked@<method>), never a
    # SetupError, under which the legacy reading stood plain unchecked (16 calls, or three heavy ones, were enough)
    if bundle.calls_left <= 0:
        return _ni.BudgetError("the delivery's cap of %d whole-image evaluations is reached" % MAX_IMAGE_CALLS)
    setup = sum(2 * (img.hi - img.lo) for img, _s, _e in t.calls)
    if setup > bundle.setup_left:
        return _ni.BudgetError("the delivery's budget of image bytes to map is spent")
    if bundle.blocks <= 0 or bundle.mem <= 0:
        return _ni.BudgetError("the delivery's native work budget is spent")
    classes, natives = bundle._pkg(vm.dex).jni_facts()
    key = (tuple((_img_digest(img), sym, entry) for img, sym, entry in t.calls), _jkey(jargs), ret, static,
           classes, natives, bundle.blocks, bundle.mem, PER_RUN_BLOCKS, PER_RUN_MEM)
    hit = _EVALS.get(key)
    if hit is None:
        hit = _put(_EVALS, key, _evaluate_now(t, jargs, ret, static, classes, natives, bundle.blocks, bundle.mem),
                   512)
    outcome, used_blocks, used_mem = hit
    bundle.calls_left -= 1
    bundle.setup_left -= setup
    bundle.blocks -= used_blocks
    bundle.mem -= used_mem
    if isinstance(outcome, tuple) and len(outcome) == 2 and isinstance(outcome[0], type):
        return outcome[0](outcome[1])                   # an error, made afresh
    return outcome


def _evaluate_now(t, jargs, ret, static, classes, natives, blocks, mem):
    """(outcome, blocks used, memory accesses used) of one evaluation from the budget state (blocks, mem); an
    error outcome is (its class, its text)."""
    used_b = used_m = 0
    outs = []
    for img, sym, entry in t.calls:
        usage = {"blocks": 0, "mem": 0}
        try:
            # KB-2 fix round 2 (the review of 4250749): every run gets only what the runs before it left of the
            # delivery's totals (each of a call's two runs was handed the whole remainder, so the total went below zero)
            r = _ni.call_jni(img, sym, jargs, ret, static, max_blocks=PER_RUN_BLOCKS, max_mem=PER_RUN_MEM,
                             usage=usage, classes=classes, natives=natives, entry=entry,
                             total_blocks=blocks - used_b, total_mem=mem - used_m)
        except _ni.EmulationError as e:
            return (type(e), str(e)), used_b + usage["blocks"], used_m + usage["mem"]
        used_b += usage["blocks"]
        used_m += usage["mem"]
        outs.append((r.kind, _freeze(r.value), tuple(sorted((k, tuple(v)) for k, v in r.commits.items())),
                     r.arr_arg))
    if any(o != outs[0] for o in outs[1:]):
        return (_ni.EmulationError, "the native libraries binding the method disagree"), used_b, used_m
    kind, value, commits, arr_arg = outs[0]
    return (kind, value, dict(commits), arr_arg), used_b, used_m


# --------------------------------------------------------------------------------------- codes and keys
def reset():
    _LEGACY_CODES.clear()
    _IMAGE_CODES.clear()


def note(vm, code):
    """Record whether the VM run that produced `code` needed the whole-image path or a demoted binding."""
    flags = frozenset(getattr(vm, "_kb2_flags", frozenset()))
    if flags:
        _IMAGE_CODES[code] = _IMAGE_CODES.get(code, frozenset()) | flags
    else:
        _LEGACY_CODES.add(code)


def _ordered(flags):
    """The demotions of `flags` in their fixed order, each base flag before its '@<why>' forms (sorted)."""
    out = []
    for base in _DEMOTIONS:
        if base in flags:
            out.append(base)
        out += sorted(f for f in flags if f.startswith(base + "@"))
    return out


def image_suffix(codes):
    """'' when every code is proven by a run with no whole-image reading and no demoted binding, else the route
    suffix to add: the native part (+native-cstr over +native-image), then each demotion in a fixed order.

    KB-2 fix round 2 (the review of 4250749, item c): the flags of EVERY run that produced one of the codes count. A
    code a flagged run gave was exempt when an unflagged run gave the same code too (a pure-Java entry, say), so the
    demotion was dropped and the answer went plain, though on a device the flagged entry runs another function (a
    RegisterNatives binding an unmodelled JNI_OnLoad hides) and the package yields two codes."""
    flags = set()
    for c in codes:
        f = _IMAGE_CODES.get(c)
        if f:
            flags |= f
    if not flags:
        return ""
    suf = ROUTE_CSTR if ROUTE_CSTR in flags else (ROUTE_IMAGE if ROUTE_IMAGE in flags else "")
    return suf + "".join(_ordered(flags))


def keyed(key, route, codes):
    """(key, route) for an answer over `codes`: unchanged unless a code depends on the whole-image path or a
    demoted binding, then a NEW key and route (never judged, so the answer is an unsure pick until the judge
    accepts it)."""
    suf = image_suffix(codes)
    if not suf:
        return key, route
    return key + suf, route + suf
