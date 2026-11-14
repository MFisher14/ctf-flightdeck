#!/usr/bin/env python3
"""Automatic decoder-function discovery for a native ELF, bound to the whole-image emulator (B-166).

``native_behavior.py`` answers one narrow shape: the question states an integer argument and the ELF entry
point calls the decoder directly.  This module finds the decoder without being told where it is:

1. **Function map.**  Every function start the image shows: symbols (when not stripped), the entry point,
   constructors, and the target of every direct ``call`` / ``bl`` in the executable segments (so a stripped
   image still has its functions), and the start a conservative scan finds after a body's last ``ret`` or
   jump when nothing before it reaches it (a routine nothing calls).  PLT stubs are read through the image's
   relocation plan: a stub bound to a function of the same image resolves to it, the others are imports.
2. **Call-site binding.**  Each function body is read once.  A small register tracker follows what the
   argument registers hold at each direct call: an integer constant, a pointer into the image
   (``lea``/``adrp+add``, or a GOT load the relocation plan resolves), or the address of a stack buffer with
   the bytes the caller is known to have stored in it (x86-64: integer and constant vector stores).  The
   callee's arity is the set of argument registers it reads before writing them.  A call whose arguments
   are all bound is a *binding*: the call the program itself makes, rebuilt.
3. **Leads.**  B-011's decompile-on-intake pseudocode (``recon/decompile/<file>/*.c``) is read for the
   calls ``main``, the entry and the constructors make, with their literal arguments; a literal fills an
   argument the call-site scan could not bind.  B-026's readers (``invert_checks.find_check_candidates``
   and ``recognise_mixer_function``) mark the functions that look like a check and the ones that are an
   invertible word mixer; a looped check B-026 refuses to lift is named as such.
4. **Ranking.**  Structure only, never a constant: a bound call site, a lead, a loop, transform arithmetic,
   byte and table access, a symbol name; calls to unmodelled imports count against.
5. **Evaluation.**  ``native_image.emulate_call`` runs the candidate in the whole loaded image with the
   bound arguments (two layouts must agree; undefined reads decline).  An image pointer is passed as the
   image's own pointer, a stack buffer as an output buffer holding exactly the bytes the caller was seen to
   store (every other byte undefined), so a buffer filled in a way the scan did not follow declines instead
   of decoding zeros.  What the call prints through puts / putchar / printf / write is captured and is
   output too (a function that only prints, with no decoder structure, is not tried).  An argument nothing binds is passed as an undefined output buffer
   too: a function that only writes through it produces its output, one that reads through it or uses it
   as a number declines.  A function nothing calls directly (the classic never-called flag routine) is
   tried the same way when its structure looks like a decoder.  Writes to the image's globals are
   reported as output.  The exact x86-64 evaluator of ``native_behavior`` runs beside it for
   integer/pointer calls: when both produce a value and the values differ the call declines, and it
   stands in for Unicorn only where ``native_emulate``'s Darwin/arm64 guard turned Unicorn off.

A call is evaluated out of its context: what the program did before the call (a key set up by an earlier
function, input read at run time) is not replayed.  The result is what the function does in the freshly
loaded image with the arguments shown, which is why a flag-format output is a ``candidate``, two different
ones are ``unsure``, and every output names its binding.

Nothing of the sample is run on the host: the image is read, and functions of it are emulated in
Unicorn's own memory (or interpreted by the bounded evaluator).  Discovery is heuristic; a decoder behind
unusual control flow, an environment check or a run-time argument still needs an agent, and is reported
as a ranked lead with the reason it was not evaluated.

Engine entry: ``solve(challenge_dir, profile)``.  Library: ``analyse``, ``decompile_leads``,
``check_leads``, ``rank``, ``evaluate``, ``unary_rows``.
"""
from __future__ import annotations

import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import native_behavior as nb  # noqa: E402  (sibling: the exact evaluator, Decline, register aliases)

Decline = nb.Decline

_ENGINE = "binary.decoder_discovery"

# ----------------------------------------------------------------------------- bounds (hard caps)
MAX_ELF_FILES = 8              # ELF files tried by solve(); the rest are named, not tried
MAX_ELF_BYTES = 32 << 20       # native_image's own image cap
MAX_SWEEP_BYTES = 8 << 20      # executable bytes swept for call targets
MAX_FUNCS = 8192               # function starts kept per image
MAX_FUNC_BYTES = 16384         # bytes of one function body read
MAX_SCAN_INSNS = 400_000       # instructions read in one image (all function bodies together)
MAX_BINDINGS = 4               # bound calls evaluated per candidate
MAX_EVALS = 48                 # emulated calls per image
MAX_BLOCKS = 50_000            # work per emulated call (translated blocks / memory accesses)
MAX_MEM = 200_000
OUT_SIZE = 4096                # bytes of an output buffer handed to a decoder
MAX_LEAD_FILES = 64            # B-011 pseudocode files read per binary
MAX_LEAD_BYTES = 1 << 20       # bytes read of one pseudocode file
MAX_LEADS = 256                # calls kept from the pseudocode of one binary
MAX_CHECK_FUNCS = 512          # functions handed to B-026's readers
LEAD_MIN = 25                  # the score at which an unevaluated candidate is reported as a lead
EVAL_MIN = 10                  # the score below which a call nothing in the image makes is not tried
MAX_REPORT = 12                # evidence lines per kind in one result
MIN_STRING = 4                 # a returned pointer is reported as a string from this many text bytes on
MAX_GAP_ROUNDS = 8             # passes of the stripped-image function-start scan (each splits once per body)
SCAN_GAPS = True               # the function-start scan for stripped images (Model._gap_starts) runs
_STATIC_CTORS = "a static image's constructor table is not modelled"   # native_image's load-phase decline

X86_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
X86_CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
A64_ARGS = tuple("x%d" % i for i in range(8))
A64_CALLER_SAVED = tuple("x%d" % i for i in range(19)) + ("x30",)

_X86_TRANSFORM = frozenset({
    "xor", "rol", "ror", "rcl", "rcr", "shl", "sal", "shr", "sar", "imul", "mul", "not", "neg", "bswap",
    "pxor", "xorps", "xorpd", "vpxor", "vxorps", "paddb", "psubb", "vpaddb", "vpsubb", "pshufb", "vpshufb",
    "pmullw", "pmulld", "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq"})
_X86_ENV = frozenset({"syscall", "sysenter", "int", "cpuid", "rdtsc", "rdtscp", "rdrand", "rdseed", "xgetbv",
                      "in", "out", "hlt"})
_A64_TRANSFORM = frozenset({"eor", "eon", "ror", "lsl", "lsr", "asr", "mul", "madd", "msub", "mvn", "bic", "orn",
                            "rev", "rev16", "rev32", "extr", "umulh", "smulh", "umull", "smull", "eor3"})
_A64_ENV = frozenset({"svc", "hvc", "smc", "mrs", "msr", "sys", "sysl", "brk"})
_A64_BYTE = frozenset({"ldrb", "strb", "ldrsb", "ldurb", "sturb", "ldursb"})
_A64_CBRANCH = frozenset({"cbz", "cbnz", "tbz", "tbnz"})
_X86_VMOV = frozenset({"movaps", "movups", "movdqa", "movdqu", "vmovaps", "vmovups", "vmovdqa", "vmovdqu"})
_X86_PAD = frozenset({"nop", "int3", "xchg"})      # alignment padding between functions (xchg ax, ax)
_VREG = re.compile(r"[xyz]mm(\d{1,2})$")

# arity of the libc subset native_image models (how many of the caller's own arguments a call passes on)
_LIBC_ARITY = {"strlen": 1, "memcpy": 3, "memmove": 3, "memset": 3, "memcmp": 3, "strcmp": 2, "strncmp": 3,
               "strcpy": 2, "strncpy": 3, "strchr": 2, "malloc": 1, "calloc": 2, "realloc": 2, "free": 1}

_NAME_HINT = re.compile(r"dec(?:ode|rypt|ipher)|deobf|unscramble|unmask|unxor|unpack|xor|flag|secret|check|"
                        r"verif|valid", re.I)


# ----------------------------------------------------------------------------- model
@dataclass
class Func:
    addr: int
    end: int = 0
    name: str | None = None
    sources: set = field(default_factory=set)      # symbol | entry | ctor | call-target | decompile
    stub: tuple | None = None                      # ("resolved", vaddr) | ("libc", name) | ("import", name)
    scan: "Scan | None" = None
    arity: int | None = None                       # argument registers read before written; None = not scanned

    @property
    def label(self) -> str:
        return self.name or "fcn.%08x" % self.addr


@dataclass(frozen=True)
class Site:
    caller: int
    addr: int
    target: int
    args: tuple            # one Val or None per argument register
    tail: bool = False


@dataclass
class Scan:
    insns: int = 0
    loops: int = 0
    transform: int = 0
    byte_mem: int = 0
    table: int = 0
    cmps: int = 0
    env: int = 0
    indirect: int = 0
    returns: bool = False
    truncated: bool = False
    used: set = field(default_factory=set)         # argument indices the body itself reads first
    passes: list = field(default_factory=list)     # per direct call to a function of the image or a modelled
    #                                                 libc function: (vaddr | ("libc", name), argument indices
    #                                                 this function had not written when it made the call)
    imports: list = field(default_factory=list)    # names of unmodelled imports called
    sites: list = field(default_factory=list)


@dataclass(frozen=True)
class Lead:
    """One call read from B-011's pseudocode: the callee, its literal arguments (None where the argument
    is not a literal) and where it was read."""
    target: int
    args: tuple
    source: str


@dataclass(frozen=True)
class Binding:
    args: tuple
    source: str
    site: int | None = None
    open: bool = False         # an argument nothing binds is passed as a fresh, undefined output buffer


@dataclass
class Candidate:
    func: Func
    score: int
    reasons: tuple
    bindings: list
    unbound: str = ""          # why no binding was built, when there is none

    @property
    def addr(self) -> int:
        return self.func.addr

    @property
    def name(self) -> str:
        return self.func.label


@dataclass(frozen=True)
class Output:
    kind: str                  # string | buffer | global | stdout | stderr | return | return32
    data: object               # bytes for string/buffer/global, int for return/return32
    where: int | None = None   # image vaddr of a changed global

    def text(self) -> str:
        """The output as text for a flag scan (latin-1, so every byte survives)."""
        if isinstance(self.data, (bytes, bytearray)):
            return bytes(self.data).decode("latin-1")
        return ""

    def show(self) -> str:
        if isinstance(self.data, (bytes, bytearray)):
            head = bytes(self.data).split(b"\x00", 1)[0]
            if head and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in head):
                return "%s %r" % (self.kind, head.decode("ascii"))
            return "%s hex %s" % (self.kind, bytes(self.data)[:64].hex())
        return "%s %#x" % (self.kind, self.data)


@dataclass
class Outcome:
    outputs: list
    engine: str                # native_image | bounded_x86
    stateful: bool = False     # the call changed the image's writable memory
    pristine: bool = False     # a static image: its constructor table is not modelled, so none was run


class Model:
    """One loaded image with its function map, scans and call sites."""

    def __init__(self, data: bytes, extra=()):
        """``extra``: further function starts (image vaddrs) a lead source named, e.g. B-011 pseudocode."""
        ni = _native()
        try:
            img = ni.load(data)
        except Exception as exc:  # noqa: BLE001 - a malformed ELF is data; the caller names the skip
            raise Decline(str(exc))
        if img.problem:
            raise Decline(img.problem)
        self.ni, self.img, self.data = ni, img, bytes(data)
        self.x86 = img.arch == getattr(ni, "ARCH_X86_64", "x86-64")
        self.notes: list[str] = []                # bounds that were hit: the analysis is incomplete
        self.slots = {off: (kind, payload) for off, kind, payload in img.plan}
        self.entry = struct.unpack_from("<Q", self.data, 24)[0]
        self.funcs: dict[int, Func] = {}
        self.sites: list[Site] = []
        self._by_target: dict[int, list] = {}
        self._capstone()
        self._map_functions(extra)
        self._scan_all()
        self._resolve_arity()

    # ------------------------------------------------------------------ disassembler
    def _capstone(self):
        try:
            import capstone
        except Exception as exc:  # noqa: BLE001 - ImportError, or a None entry in sys.modules
            raise RuntimeError("decoder_discovery needs capstone in the venv (pinned in requirements.in); "
                               "not importable") from exc
        self.cs = capstone
        if self.x86:
            from capstone import x86 as const
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.lite = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            from capstone import arm64 as const
            self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            self.lite = None
        self.const = const
        self.md.detail = True

    # ------------------------------------------------------------------ image helpers
    def exec_segments(self):
        """[(vaddr, file-backed code bytes)] of the executable PT_LOADs."""
        out = []
        for va, _memsz, filesz, off, flags in self.img.loads:
            if flags & 1 and filesz:
                out.append((va, self.img.data[off:off + filesz]))
        return out

    def code(self, lo: int, hi: int) -> bytes:
        for va, seg in self.exec_segments():
            if va <= lo < va + len(seg):
                return seg[lo - va:min(hi, va + len(seg)) - va]
        return b""

    def in_image(self, vaddr: int) -> bool:
        return self.img.seg_of(vaddr) is not None

    def data_symbols(self):
        """{name: vaddr} of the image's defined data objects (none in a stripped image)."""
        out = {}
        for sym in list(self.img.symtab) + list(self.img.dynsyms):
            if sym.type == 1 and sym.name and sym.shndx not in (0, 0xFFF1, 0xFFF2) and self.in_image(sym.value):
                out.setdefault(sym.name, sym.value)
        return out

    def is_data(self, vaddr: int) -> bool:
        """True for an address inside a non-executable segment, past the ELF and program headers."""
        seg = self.img.seg_of(vaddr)
        if seg is None or seg[4] & 1:
            return False
        phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        return not (seg[3] == 0 and vaddr - seg[0] < 64 + 56 * phnum)

    def const_bytes(self, vaddr: int, n: int):
        """``n`` file-backed bytes at ``vaddr`` of a segment the program cannot write (so what the code
        loads from there is what the file holds: no relocation and no constructor changes it); else None."""
        seg = self.img.seg_of(vaddr)
        if seg is None or seg[4] & 2 or vaddr + n > seg[0] + seg[2]:
            return None
        return self.img.file_bytes(vaddr, n)

    def pointer_slot(self, slot: int):
        """The image vaddr a relocated 8-byte slot holds, when the relocation plan says it is one."""
        got = self.slots.get(slot)
        if got and got[0] in ("rel", "sym", "abs") and isinstance(got[1], int) and self.in_image(got[1]):
            return got[1]
        return None

    # ------------------------------------------------------------------ function map
    def _add(self, addr: int, name, source: str):
        if not nb._in_exec(self.img, addr):
            return None
        f = self.funcs.get(addr)
        if f is None:
            if len(self.funcs) >= MAX_FUNCS:
                if not any("function starts" in n for n in self.notes):
                    self.notes.append("more than %d function starts: the rest are not mapped" % MAX_FUNCS)
                return None
            f = self.funcs[addr] = Func(addr)
        f.sources.add(source)
        if name and not f.name:
            f.name = name
        return f

    def _map_functions(self, extra=()):
        img = self.img
        for addr in sorted(extra):
            self._add(addr, None, "decompile")
        for s in list(img.symtab) + list(img.dynsyms):
            if s.type == 2 and s.value and s.shndx not in (0, 0xFFF1, 0xFFF2):
                self._add(s.value, s.name or None, "symbol")
        for name, va in sorted(img.exports().items()):
            self._add(va, name, "symbol")
        if self.entry:
            self._add(self.entry, None, "entry")
        for kind, va in img.constructors():
            target = va if kind == "func" else self.pointer_slot(va)
            if target is not None:
                self._add(target, None, "ctor")
        swept = 0
        for va, code in self.exec_segments():
            if swept + len(code) > MAX_SWEEP_BYTES:
                self.notes.append("executable bytes beyond %d were not swept for call targets" % MAX_SWEEP_BYTES)
                code = code[:max(0, MAX_SWEEP_BYTES - swept)]
            swept += len(code)
            for target in sorted(self._sweep(va, code)):
                self._add(target, None, "call-target")
        self._set_ends()
        for f in self.funcs.values():
            f.stub = self._stub(f)
        if SCAN_GAPS:
            # A stripped image names only what is called or exported: a routine nothing calls (the classic
            # never-called flag function) has no start.  Look for one after each body's last instruction
            # (in an image with its symbol table every such start is already named, so nothing is added).
            for _round in range(MAX_GAP_ROUNDS):
                # a start found inside a body is never a known start: the body ends at the next one
                new = [a for f in list(self.funcs.values()) if f.stub is None for a in self._gap_starts(f)]
                if not new:
                    break
                for a in new:
                    self._add(a, None, "gap")
                self._set_ends()
                for a in new:
                    if a in self.funcs:
                        self.funcs[a].stub = self._stub(self.funcs[a])
            else:
                self.notes.append("the function-start scan stopped after %d rounds" % MAX_GAP_ROUNDS)

    def _set_ends(self):
        order = sorted(self.funcs)
        for va, code in self.exec_segments():
            inside = [a for a in order if va <= a < va + len(code)]
            for a, nxt in zip(inside, inside[1:] + [va + len(code)]):
                self.funcs[a].end = nxt

    def _gap_starts(self, f: Func):
        """The function start a stripped body hides, if any: the first instruction after a ``ret`` or an
        unconditional direct jump and its alignment padding, when nothing before it can reach it.

        Conservative by construction: control enters the code after a ``ret`` only through a branch, so the
        split is refused when any direct branch before that point targets it or anything after it in the
        body, when an indirect jump (a jump table) comes before it, and on x86-64 when the address is not
        16-byte aligned (compilers align function starts; code inside a function is not padded to them).
        A wrong split costs ranking only, never a value: every output still comes from emulating the real
        bytes from the start the program uses."""
        code = self.code(f.addr, min(f.end, f.addr + MAX_FUNC_BYTES))
        far, indirect, ended = -1, False, False
        if self.x86:
            rows = ((a, s, mn, op) for a, s, mn, op in self.lite.disasm_lite(code, f.addr))
        else:
            rows = ((i.address, i.size, i.mnemonic, i.op_str) for i in self.md.disasm(code, f.addr))
        for addr, _size, mn, op in rows:
            if ended and mn in (_X86_PAD if self.x86 else ("nop",)):
                continue
            if ended and addr > f.addr and far < addr and not indirect and (not self.x86 or addr % 16 == 0):
                return [addr]
            ended = False
            if self.x86:
                target = int(op, 16) if mn.startswith("j") and op.startswith("0x") else None
                if mn.startswith("j") and target is None:
                    indirect = True
                ended = mn in ("ret", "retn") or (mn == "jmp" and target is not None)
            else:
                target = None
                if mn == "b" or mn.startswith("b.") or mn in _A64_CBRANCH:
                    last = op.rsplit("#", 1)[-1] if "#" in op else ""
                    target = int(last, 16) if last.startswith("0x") else None
                if mn == "br":
                    indirect = True
                ended = mn == "ret" or (mn == "b" and target is not None)
            if target is not None and target < f.end:          # at f.end or past it: a known function
                far = max(far, target)
        return []

    def _sweep(self, va: int, code: bytes):
        """Targets of every direct call in one executable segment (a linear sweep; no detail)."""
        out = set()
        if not self.x86:
            for i in range(0, len(code) - 3, 4):
                word = struct.unpack_from("<I", code, i)[0]
                if word & 0xFC000000 == 0x94000000:              # BL imm26
                    off = word & 0x03FFFFFF
                    if off & 0x02000000:
                        off -= 1 << 26
                    out.add((va + i + 4 * off) & ((1 << 64) - 1))
            return out
        window, pos, n = 1 << 16, 0, len(code)
        while pos < n:
            used = 0
            for _addr, size, mn, op in self.lite.disasm_lite(code[pos:pos + window + 16], va + pos):
                if used >= window:
                    break
                used += size
                if mn == "call" and op.startswith("0x"):
                    out.add(int(op, 16))
            pos += used if used else 1                           # an undecodable byte: resume one byte on
        return out

    def _stub(self, f: Func):
        """What a PLT stub at ``f`` jumps to, read through the relocation plan; None for a real function."""
        code = self.code(f.addr, min(f.end, f.addr + 32))
        slot = None
        if self.x86:
            for k, ins in enumerate(self.md.disasm(code, f.addr)):
                if k >= 2:
                    break
                if ins.mnemonic == "endbr64":
                    continue
                ops = ins.operands
                if ins.mnemonic.split()[-1] == "jmp" and len(ops) == 1 and ops[0].type == self.const.X86_OP_MEM \
                        and ops[0].mem.base and ins.reg_name(ops[0].mem.base) == "rip" and not ops[0].mem.index:
                    slot = ins.address + ins.size + ops[0].mem.disp
                break
        else:
            page, k17 = None, None
            for k, ins in enumerate(self.md.disasm(code, f.addr)):
                if k >= 5:
                    break
                ops = ins.operands
                if ins.mnemonic == "bti":
                    continue
                if ins.mnemonic == "adrp" and ins.reg_name(ops[0].reg) == "x16":
                    page = int(ops[1].imm)
                elif ins.mnemonic == "ldr" and page is not None and ins.reg_name(ops[0].reg) == "x17" \
                        and ops[1].type == self.const.ARM64_OP_MEM and ins.reg_name(ops[1].mem.base) == "x16":
                    k17 = page + ops[1].mem.disp
                elif ins.mnemonic == "br" and k17 is not None and ins.reg_name(ops[0].reg) == "x17":
                    slot = k17
                    break
                elif ins.mnemonic != "add":
                    break
        if slot is None:
            return None
        got = self.slots.get(slot)
        if got is None:
            return ("import", "?")
        kind, payload = got
        if kind in ("sym", "abs", "rel") and isinstance(payload, int) and nb._in_exec(self.img, payload):
            return ("resolved", payload)
        if kind == "trap":
            names = getattr(self.ni, "LIBC_FUNCS", ())
            return ("libc", names[payload - 1] if isinstance(payload, int) and 0 < payload <= len(names) else "?")
        if kind == "import":
            return ("import", str(payload))
        return ("import", "?")

    def resolve(self, target: int):
        """(function vaddr | None, stub | None) for a direct call target, through a PLT stub."""
        f = self.funcs.get(target)
        if f is None:
            return (target if nb._in_exec(self.img, target) else None), None
        if f.stub is None:
            return target, None
        if f.stub[0] == "resolved":
            return f.stub[1], None
        return None, f.stub

    # ------------------------------------------------------------------ scans
    def _scan_all(self):
        budget, cut = MAX_SCAN_INSNS, 0
        for addr in sorted(self.funcs):
            f = self.funcs[addr]
            if f.stub is not None:
                continue
            if budget <= 0:
                self.notes.append("function bodies beyond %d instructions were not read" % MAX_SCAN_INSNS)
                break
            code = self.code(f.addr, min(f.end, f.addr + MAX_FUNC_BYTES))
            insns = list(self.md.disasm(code, f.addr))
            f.scan = (_scan_x86 if self.x86 else _scan_a64)(self, f, insns)
            if sum(i.size for i in insns) < len(code) or f.end - f.addr > MAX_FUNC_BYTES:
                f.scan.truncated = True                          # undecodable bytes, or a body over the cap
            cut += f.end - f.addr > MAX_FUNC_BYTES
            budget -= len(insns)
            self.sites.extend(f.scan.sites)
            for site in f.scan.sites:
                self._by_target.setdefault(site.target, []).append(site)
        if cut:
            self.notes.append("%d function body(ies) longer than %d bytes were read in part (later call sites "
                              "in them are not seen)" % (cut, MAX_FUNC_BYTES))

    def _resolve_arity(self):
        """Arity = the argument registers a function reads before writing them, counting the ones it hands
        unwritten to a callee that reads them (a fixed point over the direct call graph)."""
        used = {a: set(f.scan.used) for a, f in self.funcs.items() if f.scan is not None}
        for _round in range(16):
            changed = False
            for a, f in self.funcs.items():
                if f.scan is None:
                    continue
                for callee, unwritten in f.scan.passes:
                    if isinstance(callee, tuple):
                        reads = set(range(_LIBC_ARITY.get(callee[1], 0)))
                    else:
                        reads = used.get(callee, set())
                    more = (reads & unwritten) - used[a]
                    if more:
                        used[a] |= more
                        changed = True
            if not changed:
                break
        for a, u in used.items():
            self.funcs[a].arity = (max(u) + 1) if u else 0

    def sites_of(self, target: int):
        return list(self._by_target.get(target, ()))


_NATIVE: list = []


def _native():
    """``solvers/common/native_image.py`` (the whole-image emulator); a named RuntimeError when it or its
    ``emulate_call`` is missing -- never a silent empty result."""
    if _NATIVE:
        return _NATIVE[0]
    try:
        import native_image
    except Exception as exc:  # noqa: BLE001 - ImportError, or native_emulate's UnicornUnavailable
        raise RuntimeError("decoder_discovery needs solvers/common/native_image.py; it did not import: "
                           "%s: %s" % (type(exc).__name__, exc)) from exc
    if not callable(getattr(native_image, "emulate_call", None)):
        raise RuntimeError("decoder_discovery: native_image has no emulate_call()")
    _NATIVE.append(native_image)
    return native_image


def analyse(data: bytes, extra=()) -> Model:
    """The function map, scans and call sites of one ELF image.  Raises ``Decline`` (named) for bytes the
    loader does not accept, ``RuntimeError`` (named) when capstone or native_image is missing.  ``extra``
    adds function starts a lead source named (see ``decompile_leads``)."""
    if not isinstance(data, (bytes, bytearray)):
        raise Decline("not bytes")
    return Model(bytes(data), extra)


# ----------------------------------------------------------------------------- x86-64 body scan
def _x86_base(ins, reg_id):
    a = nb._alias(ins.reg_name(reg_id))
    return a[0] if a else None


def _x86_access(model, ins):
    try:
        r, w = ins.regs_access()
    except model.cs.CsError:
        r, w = (), ()
    return ({b for b in (_x86_base(ins, i) for i in r) if b}, {b for b in (_x86_base(ins, i) for i in w) if b})


def _scan_x86(model: Model, f: Func, insns) -> Scan:
    K = model.const
    lo, hi = f.addr, f.end
    sc = Scan()
    targets = set()
    for ins in insns:
        ops = ins.operands
        if ins.mnemonic.startswith("j") and len(ops) == 1 and ops[0].type == K.X86_OP_IMM \
                and lo <= int(ops[0].imm) < hi:
            targets.add(int(ops[0].imm))
    reg, slots, written = {}, {}, set()
    vec = {}                     # vector register number -> its 16 known bytes (a constant-pool load, a zeroing)

    def slot_key(ins, mem):
        if mem.index or not mem.base or (mem.segment and ins.reg_name(mem.segment) in ("fs", "gs")):
            return None
        base = ins.reg_name(mem.base)
        return (base, int(mem.disp)) if base in ("rsp", "rbp") else None

    def source(ins, op, bits):
        """The Val a source operand holds, read at ``bits`` wide; None when unknown."""
        if op.type == K.X86_OP_IMM:
            return ("int", int(op.imm) & ((1 << bits) - 1))
        if op.type == K.X86_OP_REG:
            a = nb._alias(ins.reg_name(op.reg))
            if a is None or a[1]:
                return None
            if a[0] == "rsp":
                return ("stk", ("rsp", 0)) if a[2] == 64 else None
            v = reg.get(a[0])
            if v is None or a[2] == 64:
                return v
            return ("int", v[1] & 0xFFFFFFFF) if a[2] == 32 and v[0] == "int" else None
        if op.type == K.X86_OP_MEM:
            key = slot_key(ins, op.mem)
            if key is not None:
                got = slots.get(key)
                if got is None:
                    return None
                size, v = got
                if size == op.size:
                    return v
                return ("int", v[1] & 0xFFFFFFFF) if v[0] == "int" and op.size == 4 and size == 8 else None
            if op.size == 8 and op.mem.base and ins.reg_name(op.mem.base) == "rip" and not op.mem.index:
                target = model.pointer_slot(ins.address + ins.size + op.mem.disp)
                return ("ptr", target) if target is not None else None
        return None

    def put(ins, op, v):
        a = nb._alias(ins.reg_name(op.reg))
        if a is None:
            return
        base, shift, bits = a
        if v is not None and bits == 64:
            reg[base] = v
        elif v is not None and bits == 32 and shift == 0 and v[0] == "int":
            reg[base] = ("int", v[1] & 0xFFFFFFFF)
        else:
            reg.pop(base, None)

    def forget_stack(base):
        for r in [r for r, v in reg.items() if v[0] == "stk" and v[1][0] == base]:
            del reg[r]
        for k in [k for k in slots if k[0] == base]:
            del slots[k]

    def drop_slots(key, size):
        """A store of ``size`` bytes to a frame slot: forget every tracked slot it may overlap.  The other
        frame register's slots are the same memory at an unknown distance, so all of those go."""
        base, disp = key
        for k in [k for k, (n, _v) in slots.items() if k[0] != base or (k[1] < disp + size and disp < k[1] + n)]:
            del slots[k]

    def stack_init(key):
        """((offset, bytes), ...) the tracked stores put in the frame from stack address ``key`` on: what a
        callee handed that address finds there (a stack string, an in/out buffer)."""
        base, disp = key
        out = []
        for (b, d), (size, v) in slots.items():
            if b != base or d < disp:
                continue
            if v[0] == "int":
                data = (v[1] & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
            elif v[0] == "bytes":
                data = v[1]
            else:
                continue                                         # an address: it differs per layout
            if d - disp + len(data) <= OUT_SIZE:
                out.append((d - disp, data))
        return tuple(sorted(out))

    def arg(v):
        if v is not None and v[0] == "stk":
            init = stack_init(v[1])
            if init:
                return ("stk", v[1], init)
        return v

    def call_site(ins, target, tail):
        fn, stub = model.resolve(target)
        unwritten = frozenset(i for i, a in enumerate(X86_ARGS) if a not in written)
        if fn is not None:
            sc.sites.append(Site(f.addr, ins.address, fn, tuple(arg(reg.get(a)) for a in X86_ARGS), tail))
            sc.passes.append((fn, unwritten))
        elif stub is not None and stub[0] == "libc":
            sc.passes.append((stub, unwritten))
        elif stub is not None:
            sc.imports.append(stub[1])
        else:
            sc.indirect += 1

    for ins in insns:
        if ins.address in targets:
            reg.clear()
            slots.clear()
            vec.clear()
        mn, ops = ins.mnemonic, ins.operands
        sc.insns += 1
        if mn in ("nop", "endbr64", "int3"):
            continue                                             # padding and markers: no state, no feature
        reads, writes = _x86_access(model, ins)
        zeroing = (mn in ("xor", "sub", "pxor", "xorps") and len(ops) == 2
                   and ops[0].type == ops[1].type == K.X86_OP_REG and ops[0].reg == ops[1].reg)
        if zeroing:
            reads -= {_x86_base(ins, ops[0].reg)}
        for i, a in enumerate(X86_ARGS):
            if a in reads and a not in written:
                sc.used.add(i)
        # ---- features
        if mn in _X86_TRANSFORM and not zeroing:
            sc.transform += 1
        if mn in ("cmp", "test"):
            sc.cmps += 1
        if mn in _X86_ENV:
            sc.env += 1
        if mn in ("ret", "retn"):
            sc.returns = True
        for op in ops:
            if op.type == K.X86_OP_MEM:
                if op.size == 1:
                    sc.byte_mem += 1
                if op.mem.index:
                    sc.table += 1
                if op.mem.segment and ins.reg_name(op.mem.segment) in ("fs", "gs"):
                    sc.env += 1                                  # thread or process state
        # ---- control flow
        if mn == "call":
            if len(ops) == 1 and ops[0].type == K.X86_OP_IMM:
                call_site(ins, int(ops[0].imm), False)
            else:
                sc.indirect += 1
            for a in X86_CALLER_SAVED:
                reg.pop(a, None)
            slots.clear()
            vec.clear()                                          # every vector register is caller-saved
            written |= set(X86_CALLER_SAVED)
            continue
        if mn.startswith("j"):
            if len(ops) == 1 and ops[0].type == K.X86_OP_IMM:
                t = int(ops[0].imm)
                if lo <= t <= ins.address:
                    sc.loops += 1
                elif mn == "jmp" and not lo <= t < hi and t in model.funcs:
                    call_site(ins, t, True)                      # a tail call
            else:
                sc.indirect += 1
            if mn == "jmp":
                reg.clear()
                slots.clear()
                vec.clear()
            continue
        # ---- the register tracker
        handled = False
        vdst = _VREG.match(ins.reg_name(ops[0].reg)) if ops and ops[0].type == K.X86_OP_REG else None
        if mn in _X86_VMOV and len(ops) == 2:
            # Only the low 16 bytes of a vector register are tracked: an xmm move is all of them, and a
            # ymm / zmm move's low 16 bytes are the xmm register's (a load's first 16, a store's first 16).
            dst, src = ops
            data = None
            if src.type == K.X86_OP_REG:
                sv = _VREG.match(ins.reg_name(src.reg))
                data = vec.get(int(sv.group(1))) if sv else None
            elif src.type == K.X86_OP_MEM and ins.reg_name(src.mem.base) == "rip":   # rip takes no index
                data = model.const_bytes(ins.address + ins.size + src.mem.disp, 16)
            if vdst is not None:
                if data is not None:
                    vec[int(vdst.group(1))] = data
                else:
                    vec.pop(int(vdst.group(1)), None)
                handled = True
            elif dst.type == K.X86_OP_MEM:
                key = slot_key(ins, dst.mem)
                if key is not None:
                    drop_slots(key, dst.size)
                    if data is not None:
                        slots[key] = (16, ("bytes", data))
                else:
                    slots.clear()                                # a store through an unknown pointer
                handled = True
        elif zeroing and vdst is not None:
            vec[int(vdst.group(1))] = bytes(16)                  # pxor / xorps of a register with itself
            handled = True
        elif mn in ("mov", "movabs") and len(ops) == 2:
            dst, src = ops
            if dst.type == K.X86_OP_REG:
                put(ins, dst, source(ins, src, dst.size * 8))
                handled = True
            elif dst.type == K.X86_OP_MEM:
                key = slot_key(ins, dst.mem)
                if key is not None:
                    v = source(ins, src, dst.size * 8)
                    drop_slots(key, dst.size)
                    if v is not None and (v[0] == "int" or dst.size == 8):
                        slots[key] = (dst.size, v)
                else:
                    slots.clear()                                # a store through an unknown pointer
                handled = True
        elif mn == "lea" and len(ops) == 2 and ops[1].type == K.X86_OP_MEM:
            mem, v = ops[1].mem, None
            if mem.base and not mem.index and not mem.segment:
                base = ins.reg_name(mem.base)
                if base == "rip":
                    target = ins.address + ins.size + mem.disp
                    v = ("ptr", target) if model.in_image(target) else None
                elif base in ("rsp", "rbp"):
                    v = ("stk", (base, int(mem.disp)))
                else:
                    a = nb._alias(base)
                    old = reg.get(a[0]) if a and a[2] == 64 else None
                    if old is not None and old[0] == "ptr":
                        v = ("ptr", old[1] + mem.disp) if model.in_image(old[1] + mem.disp) else None
                    elif old is not None and old[0] == "stk":
                        v = ("stk", (old[1][0], old[1][1] + int(mem.disp)))
            put(ins, ops[0], v if ops[0].size == 8 else None)
            handled = True
        elif zeroing and mn in ("xor", "sub"):
            put(ins, ops[0], ("int", 0))
            handled = True
        elif mn in ("add", "sub") and len(ops) == 2 and ops[0].type == K.X86_OP_REG \
                and ops[1].type == K.X86_OP_IMM and ops[0].size == 8 \
                and ins.reg_name(ops[0].reg) not in ("rsp", "rbp"):
            v = reg.get(ins.reg_name(ops[0].reg))
            d = int(ops[1].imm) if mn == "add" else -int(ops[1].imm)
            if v is not None and v[0] == "int":
                v = ("int", (v[1] + d) & ((1 << 64) - 1))
            elif v is not None and v[0] == "ptr":
                v = ("ptr", v[1] + d) if model.in_image(v[1] + d) else None
            else:
                v = None
            put(ins, ops[0], v)
            handled = True
        if not handled:
            for b in writes:
                reg.pop(b, None)
            if vdst is not None:
                vec.pop(int(vdst.group(1)), None)                # any other write to a vector register
            if ops and ops[0].type == K.X86_OP_MEM and mn not in ("cmp", "test"):
                key = slot_key(ins, ops[0].mem)
                if key is not None:
                    drop_slots(key, max(1, ops[0].size))
                else:
                    slots.clear()
        for base in ("rsp", "rbp"):
            if base in writes:
                forget_stack(base)                               # the frame moved: its offsets are stale
        written |= writes
    return sc


# ----------------------------------------------------------------------------- AArch64 body scan
def _a64_base(name):
    if not name:
        return None
    if name in ("sp", "wsp"):
        return "sp"
    if name == "fp":
        return "x29"
    if name == "lr":
        return "x30"
    m = re.fullmatch(r"([xw])(\d{1,2})", name)
    return "x%s" % m.group(2) if m else None


_A64_NO_DEST = frozenset({"cmp", "cmn", "tst", "ccmp", "ccmn", "cbz", "cbnz", "tbz", "tbnz", "str", "strb",
                          "strh", "stur", "sturb", "sturh", "stp", "br", "blr", "ret", "msr", "prfm", "b", "bl"})
_A64_TWO_DEST = frozenset({"ldp", "ldpsw"})


def _a64_access(model, ins):
    """(registers read, registers written) of one instruction, from its operands.  capstone's own access
    lists are not used here: for the compare aliases (``cmp w1, #1``) they report the compared register
    as written, which would hide an argument the function reads."""
    K = model.const
    mn, ops = ins.mnemonic, ins.operands
    ndest = 0 if (mn in _A64_NO_DEST or mn.startswith("b.")) else 2 if mn in _A64_TWO_DEST else 1
    reads, writes = set(), set()
    for i, op in enumerate(ops):
        if op.type == K.ARM64_OP_REG:
            base = _a64_base(ins.reg_name(op.reg))
            if base:
                (writes if i < ndest else reads).add(base)
        elif op.type == K.ARM64_OP_MEM:
            for r in (op.mem.base, op.mem.index):
                base = _a64_base(ins.reg_name(r)) if r else None
                if base:
                    reads.add(base)
            if ins.writeback and op.mem.base:
                base = _a64_base(ins.reg_name(op.mem.base))
                if base:
                    writes.add(base)
    if mn == "movk":
        reads |= writes                                          # movk keeps the other bits of its target
    return reads, writes


def _scan_a64(model: Model, f: Func, insns) -> Scan:
    K = model.const
    lo, hi = f.addr, f.end
    sc = Scan()
    targets = set()

    def branch_target(ins):
        ops = ins.operands
        if (ins.mnemonic == "b" or ins.mnemonic.startswith("b.") or ins.mnemonic in _A64_CBRANCH) \
                and ops and ops[-1].type == K.ARM64_OP_IMM:
            return int(ops[-1].imm)
        return None

    for ins in insns:
        t = branch_target(ins)
        if t is not None and lo <= t < hi:
            targets.add(t)
    reg, written = {}, set()

    def name(op):
        return ins.reg_name(op.reg)

    def put(dst, v):
        base = _a64_base(dst)
        if base is None or base == "sp":
            return
        if v is not None and dst.startswith("w"):
            v = ("int", v[1] & 0xFFFFFFFF) if v[0] == "int" else None
        if v is None:
            reg.pop(base, None)
        else:
            reg[base] = v

    def call_site(ins, target, tail):
        fn, stub = model.resolve(target)
        unwritten = frozenset(i for i, a in enumerate(A64_ARGS) if a not in written)
        if fn is not None:
            args = tuple(v if v is not None and v[0] != "page" else None for v in (reg.get(a) for a in A64_ARGS))
            sc.sites.append(Site(f.addr, ins.address, fn, args, tail))
            sc.passes.append((fn, unwritten))
        elif stub is not None and stub[0] == "libc":
            sc.passes.append((stub, unwritten))
        elif stub is not None:
            sc.imports.append(stub[1])
        else:
            sc.indirect += 1

    for ins in insns:
        if ins.address in targets:
            reg.clear()
        mn, ops = ins.mnemonic, ins.operands
        sc.insns += 1
        reads, writes = _a64_access(model, ins)
        for i, a in enumerate(A64_ARGS):
            if a in reads and a not in written:
                sc.used.add(i)
        # ---- features
        if mn in _A64_TRANSFORM:
            sc.transform += 1
        if mn in ("cmp", "cmn", "tst", "ccmp"):
            sc.cmps += 1
        if mn in _A64_ENV:
            sc.env += 1
        if mn in _A64_BYTE:
            sc.byte_mem += 1
        if mn == "ret":
            sc.returns = True
        for op in ops:
            if op.type == K.ARM64_OP_MEM and op.mem.index:
                sc.table += 1
        # ---- control flow
        if mn == "bl":
            if len(ops) == 1 and ops[0].type == K.ARM64_OP_IMM:
                call_site(ins, int(ops[0].imm), False)
            else:
                sc.indirect += 1
            for a in A64_CALLER_SAVED:
                reg.pop(a, None)
            written |= set(A64_CALLER_SAVED)
            continue
        if mn in ("blr", "br"):
            sc.indirect += 1
            if mn == "blr":
                for a in A64_CALLER_SAVED:
                    reg.pop(a, None)
                written |= set(A64_CALLER_SAVED)
            else:
                reg.clear()
            continue
        t = branch_target(ins)
        if t is not None:
            if lo <= t <= ins.address:
                sc.loops += 1
            elif mn == "b" and not lo <= t < hi and t in model.funcs:
                call_site(ins, t, True)                          # a tail call
            if mn == "b":
                reg.clear()
            continue
        # ---- the register tracker
        v, handled = None, False
        if mn in ("mov", "movz") and len(ops) == 2 and ops[0].type == K.ARM64_OP_REG:
            if ops[1].type == K.ARM64_OP_IMM:
                v = ("int", int(ops[1].imm) & ((1 << 64) - 1))
            elif ops[1].type == K.ARM64_OP_REG:
                src = name(ops[1])
                if _a64_base(src) == "sp":
                    v = ("stk", ("sp", 0))
                else:
                    v = reg.get(_a64_base(src))
                    if v is not None and src.startswith("w") and v[0] != "int":
                        v = None
            put(name(ops[0]), v)
            handled = True
        elif mn == "movk" and len(ops) == 2 and ops[1].type == K.ARM64_OP_IMM:
            old = reg.get(_a64_base(name(ops[0])))
            if old is not None and old[0] == "int":
                sh = int(ops[1].shift.value)
                v = ("int", (old[1] & ~(0xFFFF << sh)) | ((int(ops[1].imm) & 0xFFFF) << sh))
            put(name(ops[0]), v)
            handled = True
        elif mn == "adrp" and len(ops) == 2:
            put(name(ops[0]), ("page", int(ops[1].imm)))
            handled = True
        elif mn == "adr" and len(ops) == 2:
            t = int(ops[1].imm)
            put(name(ops[0]), ("ptr", t) if model.in_image(t) else None)
            handled = True
        elif mn in ("add", "sub") and len(ops) == 3 and ops[1].type == K.ARM64_OP_REG \
                and ops[2].type == K.ARM64_OP_IMM and name(ops[0]).startswith("x"):
            d = int(ops[2].imm) << int(ops[2].shift.value)
            d = d if mn == "add" else -d
            src = _a64_base(name(ops[1]))
            if src == "sp":
                v = ("stk", ("sp", d))
            else:
                old = reg.get(src)
                if old is None:
                    v = None
                elif old[0] == "page" and mn == "add":
                    v = ("ptr", old[1] + d) if model.in_image(old[1] + d) else None
                elif old[0] == "ptr":
                    v = ("ptr", old[1] + d) if model.in_image(old[1] + d) else None
                elif old[0] == "stk":
                    v = ("stk", (old[1][0], old[1][1] + d))
                elif old[0] == "int":
                    v = ("int", (old[1] + d) & ((1 << 64) - 1))
            if _a64_base(name(ops[0])) != "sp":
                put(name(ops[0]), v)
                handled = True
        elif mn == "ldr" and len(ops) == 2 and ops[1].type == K.ARM64_OP_MEM and name(ops[0]).startswith("x") \
                and not ops[1].mem.index and not ins.writeback:
            old = reg.get(_a64_base(ins.reg_name(ops[1].mem.base)))
            if old is not None and old[0] in ("page", "ptr"):
                t = model.pointer_slot(old[1] + int(ops[1].mem.disp))
                v = ("ptr", t) if t is not None else None
            put(name(ops[0]), v)
            handled = True
        if not handled:
            for b in writes:
                reg.pop(b, None)
        if "sp" in writes:
            for r in [r for r, val in reg.items() if val[0] == "stk"]:
                del reg[r]
        written |= writes
    return sc


# ----------------------------------------------------------------------------- B-011 leads
_R2_DIR_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_CALL = re.compile(r"(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
_ADDR_NAME = re.compile(r"(?:fcn|func|sub|FUN|fun)[._](?:0x)?([0-9A-Fa-f]{3,16})$")
_DATA_NAME = re.compile(r"&?\s*(?:DAT_|obj\.0x|0x)([0-9A-Fa-f]{3,16})$")
_DATA_SYMBOL = re.compile(r"&?\s*(?:obj\.|sym\.)?([A-Za-z_][A-Za-z0-9_]*)$")
_INT = re.compile(r"-?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*$")
_CAST = re.compile(r"^\(\s*(?:const\s+|unsigned\s+|signed\s+|struct\s+)*[A-Za-z_][A-Za-z0-9_]*(?:\s*\*+)?\s*\)\s*")
_GHIDRA_PIE_BASE = 0x100000


def decompile_dir(challenge_dir: Path, rel: str) -> Path:
    """Where B-011 (``decompile_intake.solve``) writes the pseudocode of handout file ``rel``."""
    safe = _R2_DIR_SAFE.sub("_", str(rel).replace("/", "__"))[:80] or "fn"
    return Path(challenge_dir) / "recon" / "decompile" / safe


def _split_args(text: str):
    """The top-level comma-separated arguments of a call whose ``(`` was just consumed; None when the
    closing parenthesis is not found within the text."""
    depth, out, cur, quote, i = 0, [], [], None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            if depth == 0:
                tail = "".join(cur).strip()
                if tail or out:
                    out.append(tail)
                return out
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    return None


def _c_string(token: str):
    """The bytes of a C string literal token (with its terminating NUL), or None."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        return None
    out, i, body = bytearray(), 0, token[1:-1]
    simple = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 0x5C, '"': 0x22, "'": 0x27, "a": 7, "b": 8, "f": 12, "v": 11}
    while i < len(body):
        ch = body[i]
        if ch == '"':
            return None                                          # two literals, or an unescaped quote
        if ch != "\\":
            if ord(ch) > 0xFF:
                return None
            out.append(ord(ch))
            i += 1
            continue
        nxt = body[i + 1:i + 2]
        if nxt == "x":
            m = re.match(r"[0-9A-Fa-f]{1,2}", body[i + 2:])
            if not m:
                return None
            out.append(int(m.group(0), 16))
            i += 2 + len(m.group(0))
        elif nxt in simple:
            out.append(simple[nxt])
            i += 2
        else:
            return None
    return bytes(out) + b"\x00"


def _lead_arg(model: Model, token: str):
    token = token.strip()
    for _ in range(3):
        stripped = _CAST.sub("", token)
        if stripped == token:
            break
        token = stripped
    lit = _c_string(token)
    if lit is not None:
        return ("bytes", lit)
    if _INT.match(token):
        return ("int", int(token.rstrip("uUlL"), 0) & ((1 << 64) - 1))
    m = _DATA_NAME.match(token)
    if m and not token.startswith("0x"):
        addr = _image_addr(model, int(m.group(1), 16), code=False)
        if addr is not None:
            return ("ptr", addr)
    m = _DATA_SYMBOL.match(token)
    if m:
        addr = model.data_symbols().get(m.group(1))
        if addr is not None:
            return ("ptr", addr)
    return None


def _image_addr(model: Model, addr: int, code: bool):
    """A decompiler's address as an image vaddr (Ghidra shows a PIE at 0x100000), or None."""
    ok = (lambda a: nb._in_exec(model.img, a)) if code else model.in_image
    if ok(addr):
        return addr
    if model.img.etype == 3 and addr >= _GHIDRA_PIE_BASE and ok(addr - _GHIDRA_PIE_BASE):
        return addr - _GHIDRA_PIE_BASE
    return None


def _lead_target(model: Model, name: str, by_name: dict):
    """The image vaddr a callee token of the pseudocode names, or None.  A C keyword (``if (``), an import
    (``sym.imp.puts``) and a local variable are simply not function names of the image."""
    m = _ADDR_NAME.search(name)
    if m:
        return _image_addr(model, int(m.group(1), 16), code=True)
    for prefix in ("sym.plt.", "plt.", "sym.", "dbg.", "fcn.", "sub.", "loc."):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return by_name.get(name)


def leads_from_text(model: Model, text: str, source: str, defined: str = ""):
    """The calls a pseudocode text makes into the image: ``[Lead]``.  ``defined`` is the function the text
    decompiles (its own signature line is not a call)."""
    by_name = {f.name: a for a, f in model.funcs.items() if f.name and f.stub is None}
    own = _lead_target(model, defined, by_name) if defined else None
    out = []
    for m in _CALL.finditer(text):
        target = _lead_target(model, m.group(1), by_name)
        if target is None or target == own:
            continue
        resolved, _stub = model.resolve(target)
        if resolved is None:
            continue
        args = _split_args(text[m.end():m.end() + 1024])
        if args is None:
            continue
        out.append(Lead(resolved, tuple(_lead_arg(model, a) for a in args), source))
        if len(out) >= MAX_LEADS:
            break
    return out


def decompile_leads(model: Model, challenge_dir, rel: str):
    """``([Lead], notes)`` from B-011's pseudocode of handout file ``rel``; ``([], [])`` when B-011 wrote
    nothing for it.  The text is data: only call expressions are read out of it.  A lead may name a
    function start the image scan did not find (``lead.target not in model.funcs``): analyse the image
    again with those starts as ``extra`` and read the leads again, as solve() does."""
    d = decompile_dir(Path(challenge_dir), rel)
    if not d.is_dir():
        return [], []
    leads, notes = [], []
    files = sorted(p for p in d.iterdir() if p.is_file() and not p.is_symlink() and p.suffix == ".c")
    if len(files) > MAX_LEAD_FILES:
        notes.append("%d more pseudocode file(s) not read" % (len(files) - MAX_LEAD_FILES))
    for p in files[:MAX_LEAD_FILES]:
        try:
            with open(p, "rb") as fh:
                raw = fh.read(MAX_LEAD_BYTES + 1)
        except OSError as exc:
            notes.append("%s unreadable (%s)" % (p.name, type(exc).__name__))
            continue
        if len(raw) > MAX_LEAD_BYTES:
            notes.append("%s read to %d bytes only" % (p.name, MAX_LEAD_BYTES))
            raw = raw[:MAX_LEAD_BYTES]
        for lead in leads_from_text(model, raw.decode("utf-8", "replace"), p.name, defined=p.stem):
            leads.append(lead)
            if len(leads) >= MAX_LEADS:
                notes.append("more than %d decompiled calls: the rest are not read" % MAX_LEADS)
                return leads, notes
    return leads, notes


# ----------------------------------------------------------------------------- B-026 leads
_CHECKS: list = []


def _invert_checks():
    """``solvers/binary/invert_checks.py`` (B-026); a named RuntimeError when it does not import."""
    if _CHECKS:
        return _CHECKS[0]
    try:
        import invert_checks
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("decoder_discovery reads B-026's leads from solvers/binary/invert_checks.py; it "
                           "did not import: %s: %s" % (type(exc).__name__, exc)) from exc
    _CHECKS.append(invert_checks)
    return invert_checks


def check_leads(model: Model):
    """B-026's view of the image's functions: ``{vaddr: [reason, ...]}``.

    ``find_check_candidates`` ranks functions by compare/arithmetic immediates; one of them that also loops
    is the looped per-character check B-026 refuses to lift.  ``recognise_mixer_function`` names the
    functions that are an invertible word mixer.  Both read i386/amd64 code only: an AArch64 image has no
    B-026 leads (``{}``), which solve() says in its notes.  At most ``MAX_CHECK_FUNCS`` functions are
    handed over; a larger image gets a note in ``model.notes``."""
    if not model.x86:
        return {}
    ic = _invert_checks()
    real = [f for a, f in sorted(model.funcs.items()) if f.stub is None and f.scan is not None]
    if len(real) > MAX_CHECK_FUNCS:
        note = "B-026's readers saw the first %d of %d functions" % (MAX_CHECK_FUNCS, len(real))
        if note not in model.notes:
            model.notes.append(note)
        real = real[:MAX_CHECK_FUNCS]
    info = {"arch": "amd64", "class": 64, "entry": model.entry or None,
            "functions": [(f.label, f.addr) for f in real],
            "exec_sections": [(".text", va, code) for va, code in model.exec_segments()]}
    out: dict[int, list] = {}
    for rank, (_name, addr) in enumerate(ic.find_check_candidates(info, max_funcs=ic.MAX_ELF_FUNCS)):
        f = model.funcs.get(addr)
        if f is None or f.scan is None or addr == model.entry:
            continue
        out.setdefault(addr, []).append(
            "B-026 check candidate #%d%s" % (rank + 1, " (looped: B-026 does not lift it)" if f.scan.loops else ""))
    for f in real:
        size = f.end - f.addr
        if size > ic.MAX_MIXER_FUNC_BYTES or f.scan.loops or f.scan.passes or f.scan.imports or f.scan.indirect:
            continue
        try:
            got = ic.recognise_mixer_function(model.code(f.addr, f.end), arch="amd64", bits=64, base=f.addr)
        except RuntimeError:
            raise
        except Exception:  # noqa: BLE001 - code the recogniser cannot read is "not a mixer"
            got = None
        if got is not None:
            out.setdefault(f.addr, []).append("B-026 mixer function (%d-bit, %d op(s))" % (got[1], len(got[0])))
    return out


# ----------------------------------------------------------------------------- ranking and binding
def _known_prefix(args):
    n = 0
    for v in args:
        if v is None:
            break
        n += 1
    return n


def _lead_variants(model: Model, args):
    """A decompiler prints an image address as a plain integer (``decode(0x2080, 0x25)``).  The argument
    lists a lead stands for: first the one where every integer that is an address of the image's data is
    that pointer, then the list as read."""
    as_ptr = tuple(("ptr", v[1]) if v is not None and v[0] == "int" and model.is_data(v[1]) else v for v in args)
    return [as_ptr, tuple(args)] if as_ptr != tuple(args) else [tuple(args)]


def _agree(model: Model, sv, lv) -> int:
    """How a call site's argument and a lead's argument at the same position compare: +1 they state the
    same value, 0 one of them says nothing, -1 they contradict each other."""
    if sv is None or lv is None:
        return 0
    if sv[0] == "stk":
        return -1                                     # a stack buffer is never a literal in the pseudocode
    if sv[0] == "int":
        if lv[0] != "int":
            return -1
        mask = 0xFFFFFFFF if sv[1] <= 0xFFFFFFFF else (1 << 64) - 1
        return 1 if (lv[1] & mask) == sv[1] else -1
    if sv[0] == "ptr":
        if lv[0] == "ptr":
            return 1 if lv[1] == sv[1] else -1
        if lv[0] == "int":
            return 1 if _image_addr(model, lv[1], code=False) == sv[1] else -1
        if lv[0] == "bytes":                          # the decompiler printed the string the pointer names
            try:
                return 1 if model.img.file_bytes(sv[1], len(lv[1])) == lv[1] else -1
            except Exception:  # noqa: BLE001 - not file-backed: not that string
                return -1
    return -1


def _align(model: Model, site_args, lead_args, arity: int):
    """The call site's first ``arity`` arguments with each unbound one taken from the lead, or None.

    A decompiler's recovered signature can carry extra leading parameters, so position alone is not
    trusted: the lead is shifted until its literals agree with what the site binds (at least one
    agreement, no contradiction, exactly one such shift).  Only when the site binds nothing at all is
    position used, and then only if the lead has exactly ``arity`` arguments."""
    site_args = tuple(site_args[:arity])
    good = []
    for k in range(max(1, len(lead_args))):
        total = 0
        for i, sv in enumerate(site_args):
            got = _agree(model, sv, lead_args[i + k] if i + k < len(lead_args) else None)
            if got < 0:
                total = -1
                break
            total += got
        if total > 0:
            good.append(k)
    if len(good) == 1:
        k = good[0]
    elif not good and all(v is None for v in site_args) and len(lead_args) == arity:
        k = 0
    else:
        return None
    return tuple(sv if sv is not None else (lead_args[i + k] if i + k < len(lead_args) else None)
                 for i, sv in enumerate(site_args))


def _bindings(model: Model, f: Func, leads):
    """Every argument list ``f`` can be called with, most certain first: ``([Binding], why none)``.

    Bound: a call site of the image whose arguments are all known; a call site completed by the literals
    of a decompile lead (``_align``); a lead alone, for a function the scan saw no call to, when the lead
    has exactly the function's arity.  Open: a call site with an argument nothing binds, or (for a
    function of at most two arguments that nothing calls directly) no call site at all -- each unbound
    argument is passed as a fresh UNDEFINED output buffer.  That is sound for any pointer the function only
    writes through, and declines otherwise: a read through it reads undefined memory, and a use of it as a
    number differs between the two layouts."""
    if f.arity is None:
        return [], "its body was not read"
    out, seen = [], set()

    def add(args, source, site, open_=False):
        if args not in seen:
            seen.add(args)
            out.append(Binding(args, source, site, open_))

    sites = model.sites_of(f.addr)
    own = [ld for ld in leads if ld.target == f.addr]
    pending = []
    for s in sites:
        n = _known_prefix(s.args)
        if n >= f.arity:
            add(tuple(s.args[:n]), "call site %#x" % s.addr, s.addr)
            continue
        completed = False
        for ld in own:
            for largs in _lead_variants(model, ld.args):
                merged = _align(model, s.args, largs, f.arity)
                if merged is not None and _known_prefix(merged) >= f.arity:
                    add(merged, "call site %#x completed by decompile lead %s" % (s.addr, ld.source), s.addr)
                    completed = True
        if not completed:
            pending.append(s)
    if not sites:                                     # a lead alone binds a function the scan saw no call to
        for ld in own:
            if len(ld.args) != f.arity:
                continue                              # a signature the binary's own arity does not confirm
            for largs in _lead_variants(model, ld.args):
                if _known_prefix(largs) >= f.arity:
                    add(tuple(largs), "decompile lead %s" % ld.source, None)
    for s in pending:
        args = tuple(s.args[i] if s.args[i] is not None else ("out", i) for i in range(f.arity))
        unbound = sum(1 for v in args if v[0] == "out")
        add(args, "call site %#x, %d unbound argument(s) passed as output buffers" % (s.addr, unbound),
            s.addr, True)
    if not sites and not out:
        if f.arity == 0:
            add((), "no arguments (nothing calls it directly)", None)
        elif f.arity <= 2:
            add(tuple(("out", i) for i in range(f.arity)),
                "no call site: its %d argument(s) passed as output buffers" % f.arity, None, True)
    if out:
        return out, ""
    return [], "takes %d argument(s) and no direct call to it was found" % f.arity


def _sinks(model: Model) -> frozenset:
    """The output imports native_image captures (``SINK_FUNCS``): a call to one is evaluated, not refused."""
    return frozenset(getattr(model.ni, "SINK_FUNCS", ()))


def _unmodelled(model: Model, sc: Scan):
    """The imports a body calls that the emulator neither models nor captures, sorted."""
    sinks = _sinks(model)
    return sorted({n for n in sc.imports if n not in sinks})


def _prints_only(model: Model, sc: Scan) -> bool:
    """A body that prints and shows no decoder structure (no loop, transform, byte or table access): what
    it prints is a constant of the image or a callee's output, which the callee's own evaluation shows."""
    sinks = _sinks(model)
    return any(n in sinks for n in sc.imports) and not (sc.loops or sc.transform or sc.byte_mem or sc.table)


def rank(model: Model, leads=(), checks=None):
    """The image's decoder candidates, best first: ``[Candidate]``.  Structure only -- never a constant."""
    checks = checks or {}
    sinks = _sinks(model)
    lead_targets: dict[int, list] = {}
    for ld in leads:
        lead_targets.setdefault(ld.target, []).append(ld)
    out = []
    for addr, f in model.funcs.items():
        sc = f.scan
        if f.stub is not None or sc is None or sc.insns == 0:
            continue
        if addr == model.entry or "ctor" in f.sources or f.name in ("_start", "_init", "_fini"):
            continue
        score, reasons = 0, []
        bindings, why = _bindings(model, f, leads)
        bound = [b for b in bindings if not b.open and (b.site is not None or b.args)]
        if bound:
            score += 40
            reasons.append("%d bound call(s)" % len(bound))
        elif any(b.site is not None for b in bindings):
            score += 15
            reasons.append("called with an unbound argument")
        if addr in lead_targets:
            score += 25
            reasons.append("called in B-011 pseudocode (%s)" % lead_targets[addr][0].source)
        for why_check in checks.get(addr, ()):
            score += 20 if "mixer" in why_check else 10
            reasons.append(why_check)
        if sc.loops:
            score += 10
            reasons.append("loop")
        if sc.transform:
            score += min(20, 2 * sc.transform)
            reasons.append("%d transform op(s)" % sc.transform)
        if sc.byte_mem:
            score += 5
            reasons.append("byte access")
        if sc.table:
            score += 5
            reasons.append("indexed access")
        if f.name and _NAME_HINT.search(f.name):
            score += 15
            reasons.append("name")
        unmodelled = _unmodelled(model, sc)
        if unmodelled:
            score -= 30
            reasons.append("calls unmodelled import(s) %s" % ", ".join(unmodelled[:4]))
        printed = sorted({n for n in sc.imports if n in sinks})
        if printed and _prints_only(model, sc):
            score -= 30
            reasons.append("only prints through %s (no loop, transform, byte or table access)"
                           % ", ".join(printed[:4]))
        elif printed:
            reasons.append("prints through %s (output captured)" % ", ".join(printed[:4]))
        if sc.env:
            score -= 30
            reasons.append("reads machine or thread state")
        if not sc.returns:
            score -= 10
            reasons.append("no return seen")
        out.append(Candidate(f, score, tuple(reasons), bindings, why))
    out.sort(key=lambda c: (-c.score, c.addr))
    return out


def unary_rows(img_or_model, argument: int):
    """For ``native_behavior.discover``: ``[(target, call site | None)]`` of the functions a question's
    stated integer argument can be bound to, when the entry point itself does not bind it.

    First every direct call anywhere in the image that passes exactly that integer as the first argument
    to a function reading no other argument.  When no call site binds it, every function that reads only
    its first argument, returns, loops or transforms, and calls nothing unmodelled.  The caller still
    requires every row to evaluate and agree."""
    model = img_or_model if isinstance(img_or_model, Model) else Model(img_or_model.data)
    rows = []
    for s in model.sites:
        f = model.funcs.get(s.target)
        if f is None or f.arity is None or f.arity > 1:
            continue
        if s.args and s.args[0] == ("int", argument & ((1 << 64) - 1)):
            rows.append((s.target, s.addr))
    if rows:
        return list(dict.fromkeys(rows))
    for c in rank(model):
        sc = c.func.scan
        if c.func.arity == 1 and sc.returns and (sc.loops or sc.transform) and not sc.imports and not sc.env \
                and not sc.indirect and not sc.truncated:
            rows.append((c.addr, None))
    return rows


# ----------------------------------------------------------------------------- evaluation
def evaluate(model: Model, addr: int, args, *, max_blocks: int = MAX_BLOCKS, max_mem: int = MAX_MEM) -> Outcome:
    """Run the function at ``addr`` with the bound ``args`` and return what it produced; ``Decline`` (with
    the reason) when nothing can be proved.

    ``args``: ``("int", value)``, ``("ptr", image vaddr)``, ``("stk", key)`` / ``("out", key)`` (a fresh
    undefined output buffer; equal keys are one buffer), ``("stk", key, ((offset, bytes), ...))`` (the same,
    with the bytes the caller stored there before the call defined) and ``("bytes", data)``.

    ``native_image.emulate_call`` is the evaluator (whole image, load phase run, two layouts, changes to
    the image's globals reported).  A static executable, whose constructor table native_image does not
    model, is read pristine instead and the outcome says so.  For an x86-64 call whose arguments are
    integers and image pointers the exact evaluator of ``native_behavior`` runs too, unless the image has
    dynamic constructors (it runs none): both producing a return value that differs declines, and it
    stands in only when ``native_emulate``'s host guard turned Unicorn off.

    The outcome lists what the call produced: a text string at the returned pointer, each output buffer's
    written prefix (a buffer the call left as the caller filled it is not output), each changed run of the
    image's globals, what it printed (puts / putchar / printf / write, captured by native_image), and --
    only when it wrote nothing -- the return register."""
    ni, img = model.ni, model.img
    call_args, bufs = [], {}
    for a in args:
        if a[0] == "int":
            call_args.append(int(a[1]))
        elif a[0] == "ptr":
            call_args.append(ni.ImagePtr(a[1]))
        elif a[0] in ("stk", "out"):
            if a not in bufs:
                bufs[a] = ni.OutBuf(OUT_SIZE, a[2] if a[0] == "stk" and len(a) > 2 else ())
            call_args.append(bufs[a])
        elif a[0] == "bytes":
            call_args.append(bytes(a[1]))
        else:
            raise Decline("an argument of kind %r is not bound" % (a[0],))
    result, native_error, pristine = None, None, False
    try:
        result = ni.emulate_call(model.data, addr, call_args, arch=img.arch, max_blocks=max_blocks,
                                 max_mem=max_mem, init="auto", state="report", output="capture")
    except ni.EmulationError as exc:
        native_error = str(exc)
    if result is None and native_error == _STATIC_CTORS:
        # A static executable's constructors (libc start-up) are not modelled.  Read the pristine image,
        # as native_behavior does, and say so: data a constructor prepares would be read unprepared.
        pristine, native_error = True, None
        try:
            result = ni.emulate_call(model.data, addr, call_args, arch=img.arch, max_blocks=max_blocks,
                                     max_mem=max_mem, init="skip", state="report", output="capture")
        except ni.EmulationError as exc:
            native_error = str(exc)
    static = None
    # The exact evaluator runs no load-time code: it may speak only for an image without dynamic
    # constructors (a static image's unmodelled table is read pristine by both evaluators).
    if model.x86 and all(a[0] in ("int", "ptr") for a in args) and not img.constructors():
        try:
            static = nb._fallback_x86(img, addr, [a if a[0] == "ptr" else a[1] for a in args])
        except Decline:
            static = None
    if result is not None:
        if static is not None:
            if result.value is not None and result.value != static[0]:
                raise Decline("native and static evaluators disagree")
        outputs = []
        # A void function leaves whatever was in the return register: a pointer there is read as a string
        # only when it is text, and the register itself is reported only when the call wrote nothing.
        if result.cstr and len(result.cstr) >= MIN_STRING \
                and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in result.cstr):
            outputs.append(Output("string", result.cstr))
        for buf in bufs.values():
            wrote = buf.written()
            if wrote and not _as_filled(buf):
                outputs.append(Output("buffer", wrote))
        for va, data in result.changes:
            outputs.append(Output("global", data, va))
        for kind in ("stdout", "stderr"):
            if getattr(result, kind, b""):
                outputs.append(Output(kind, getattr(result, kind)))
        if not outputs and result.value is not None:
            outputs.append(Output("return", result.value))
        elif not outputs and result.value32 is not None:
            outputs.append(Output("return32", result.value32))
        if not outputs:
            raise Decline("the call produced nothing the two layouts agree on")
        return Outcome(outputs, "native_image", bool(result.changes), pristine)
    # Only the host-capability guard lets the narrower evaluator stand in for Unicorn.  A loader,
    # relocation, constructor, import or semantic decline is never bypassed.
    if native_error and "unicorn engine not available" in native_error.lower():
        if static is not None:
            return Outcome([Output("return", static[0])], "bounded_x86", False, bool(img.section_constructors()))
        raise Decline("unicorn engine not available on this host and the bounded x86-64 evaluator does not "
                      "cover this call")
    raise Decline(native_error or "no evaluator")


def _as_filled(buf) -> bool:
    """True when an output buffer ends exactly as the caller filled it (its ``init``): nothing was written."""
    if not buf.init:
        return False
    data, defined = bytearray(buf.size), bytearray(buf.size)
    for off, chunk in buf.init:
        data[off:off + len(chunk)] = chunk
        defined[off:off + len(chunk)] = b"\x01" * len(chunk)
    return bytes(data) == buf.data and bytes(defined) == buf.defined


# ----------------------------------------------------------------------------- engine entry
_SKIP_DIRS = {"recon", "unpacked"}


def _handout_elfs(challenge_dir: Path, limit: int | None = None):
    """``([path], over)``: the ELF files under ``files/`` and the challenge root (intake's own output
    folders and symlinks skipped), at most ``limit`` (default ``MAX_ELF_FILES``); ``over`` counts the
    further ones."""
    import os
    limit = MAX_ELF_FILES if limit is None else limit
    seen, out, over = set(), [], 0
    for root in (challenge_dir / "files", challenge_dir):
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not (here / d).is_symlink())
            for nm in sorted(filenames):
                p = here / nm
                if p.is_symlink() or not p.is_file() or p.resolve() in seen:
                    continue
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if head != b"\x7fELF":
                    continue
                seen.add(p.resolve())
                if len(out) < limit:
                    out.append(p)
                else:
                    over += 1
    return out, over


def _fmt_args(args) -> str:
    def one(a):
        if a[0] == "int":
            return "%#x" % a[1]
        if a[0] == "ptr":
            return "&image[%#x]" % a[1]
        if a[0] == "stk":
            return "stack-buffer" if len(a) < 3 else "stack-buffer[%d byte(s) stored]" % sum(len(b) for _o, b in a[2])
        if a[0] == "out":
            return "out"
        return "%r" % (bytes(a[1]),)
    return "(" + ", ".join(one(a) for a in args) + ")"


def solve(challenge_dir, profile, *, max_evals=MAX_EVALS, max_blocks=MAX_BLOCKS, max_mem=MAX_MEM, **_opts):
    """Engine entry: find the handout ELFs' decoder functions, bind their arguments and emulate them.

    Options (``--opt key=value``): ``max_evals`` emulated calls per image, ``max_blocks`` / ``max_mem`` the
    work bound of one emulated call (translated blocks / memory accesses).  Work, never a clock.

    ``candidate`` when the emulated decoders produced exactly ONE value in the event flag format.
    ``unsure`` when they produced several different flag-format values (the decoders disagree: none is
    asserted, each is in the evidence); when they produced output that is not a flag (in the evidence,
    for an agent to finish); when ranked candidates could not be bound or evaluated (each named with its
    reason); or when the analysis was incomplete (a skipped file, a bound that was hit, a lead source
    that could not run).  ``blocked`` when capstone or native_image is missing, when no handout ELF could
    be loaded, or when nothing could be evaluated because Unicorn is guarded off on this host.  ``none``
    only when every handout ELF was analysed completely and nothing decoder-like was found.
    Nothing is run on the host: functions are emulated inside the loaded image.
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    max_evals, max_blocks, max_mem = int(max_evals), int(max_blocks), int(max_mem)
    if max_evals < 0 or max_blocks <= 0 or max_mem <= 0:
        raise ValueError("max_evals must be >= 0 and max_blocks / max_mem > 0")
    try:
        ni = _native()
        import capstone  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - a missing dependency is BLOCKED, named
        return SolverResult(status="blocked", engine=_ENGINE, notes="cannot run: %s" % exc)
    ff = flagfmt.for_profile(profile)
    files, over = _handout_elfs(challenge_dir)
    if not files:
        return SolverResult(status="none", engine=_ENGINE, notes="no ELF binary in the handout")
    incomplete: list[str] = []
    skipped: list[str] = []
    if over:
        incomplete.append("%d more ELF file(s) beyond the cap of %d not tried" % (over, MAX_ELF_FILES))
    found: list[Evidence] = []        # decoder outputs
    lead_ev: list[Evidence] = []      # ranked candidates that were not evaluated
    used_ev: list[Evidence] = []      # lead sources that were read
    flags: list[str] = []
    notes_out: list[str] = []
    lead_notes: list[str] = []
    guard_blocked = 0
    analysed = evaluated = 0
    for path in files:
        rel = str(path.relative_to(challenge_dir))
        try:
            size = path.stat().st_size
            if size > MAX_ELF_BYTES:
                skipped.append("%s: larger than %d bytes, not loaded" % (rel, MAX_ELF_BYTES))
                continue
            data = path.read_bytes()
        except OSError as exc:
            skipped.append("%s: unreadable (%s)" % (rel, type(exc).__name__))
            continue
        try:
            model = analyse(data)
        except Decline as exc:
            skipped.append("%s: not loaded (%s)" % (rel, exc))
            continue
        analysed += 1
        evals = 0                                    # emulated calls of this image
        try:
            leads, lnotes = decompile_leads(model, challenge_dir, rel)
            new = {ld.target for ld in leads} - set(model.funcs)
            if new:                                  # the pseudocode names functions the scan did not find
                model = analyse(data, extra=new)
                leads, lnotes = decompile_leads(model, challenge_dir, rel)
        except Exception as exc:  # noqa: BLE001 - pseudocode is data; a reader error is named, not fatal
            leads, lnotes = [], ["B-011 pseudocode not read (%s: %s)" % (type(exc).__name__, exc)]
        incomplete.extend("%s: %s" % (rel, n) for n in lnotes)
        if leads:
            d = decompile_dir(challenge_dir, rel)
            used_ev.append(Evidence(kind="decompile", path=str(d.relative_to(challenge_dir)),
                                    detail="%d call(s) read from B-011 pseudocode of %s" % (len(leads), rel)))
        try:
            checks = check_leads(model)
        except RuntimeError as exc:
            checks = {}
            incomplete.append("%s: B-026 leads not read (%s)" % (rel, exc))
        if not model.x86:
            lead_notes.append("%s: B-026 leads cover i386/amd64 only (this image is %s)" % (rel, model.img.arch))
        incomplete.extend("%s: %s" % (rel, n) for n in model.notes)
        ranked = rank(model, leads, checks)
        for cand in ranked:
            tag = "%s:%s@%#x" % (rel, cand.name, cand.addr)
            if not cand.bindings:
                if cand.score >= LEAD_MIN and len(lead_ev) < MAX_REPORT:
                    lead_ev.append(Evidence(kind="decoder-candidate", path=rel, detail="%s score %d [%s] not "
                                            "evaluated: %s" % (tag, cand.score, "; ".join(cand.reasons), cand.unbound)))
                continue
            refused = "it calls an unmodelled import" if _unmodelled(model, cand.func.scan) else \
                "it only prints (no decoder structure)" if _prints_only(model, cand.func.scan) else ""
            if refused:
                if cand.score >= LEAD_MIN and len(lead_ev) < MAX_REPORT:
                    lead_ev.append(Evidence(kind="decoder-candidate", path=rel, detail="%s score %d [%s] not "
                                            "evaluated: %s" % (tag, cand.score, "; ".join(cand.reasons), refused)))
                continue
            if len(cand.bindings) > MAX_BINDINGS:
                incomplete.append("%s: %d more bound call(s) not evaluated" % (tag, len(cand.bindings) - MAX_BINDINGS))
            for b in cand.bindings[:MAX_BINDINGS]:
                if (b.open or b.site is None) and cand.score < EVAL_MIN:
                    continue                         # nothing calls it and nothing marks it a decoder
                if evals >= max_evals:
                    note = "%s: evaluation cap of %d call(s) reached; lower-ranked candidates not evaluated" \
                        % (rel, max_evals)
                    if note not in incomplete:
                        incomplete.append(note)
                    break
                evals += 1
                evaluated += 1
                call = "%s%s [%s]" % (tag, _fmt_args(b.args), b.source)
                try:
                    outcome = evaluate(model, cand.addr, b.args, max_blocks=max_blocks, max_mem=max_mem)
                except Decline as exc:
                    if "unicorn engine not available" in str(exc):
                        guard_blocked += 1
                    if len(lead_ev) < MAX_REPORT:
                        lead_ev.append(Evidence(kind="decoder-candidate", path=rel,
                                                detail="%s declined: %s" % (call, exc)))
                    continue
                state = " (the call changed global state: the output is that of the first call after load)" \
                    if outcome.stateful else ""
                if outcome.pristine:
                    state += " (static image: its constructors were not run)"
                for o in outcome.outputs:
                    line = "%s -> %s via %s%s" % (call, o.show(), outcome.engine, state)
                    hit = list(ff.find_flags(o.text()))
                    if hit or len(found) < MAX_REPORT:
                        found.append(Evidence(kind="emulate", detail=line, path=rel))
                    for fl in hit:
                        if fl not in flags:
                            flags.append(fl)
                            notes_out.append("%s decodes to %s" % (call, fl))
    evidence = tuple(found + used_ev + lead_ev)
    problems = incomplete + skipped
    tail = ("; incomplete: " + "; ".join(problems)) if problems else ""
    more = ("; " + "; ".join(lead_notes)) if lead_notes else ""
    if len(flags) == 1:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=evidence, engine=_ENGINE,
                            notes=("the emulated decoders produced one flag-format value (emulated in the "
                                   "loaded image, not run): " + "; ".join(notes_out) + tail + more))
    if len(flags) > 1:
        return SolverResult(status="unsure", evidence=evidence, engine=_ENGINE,
                            notes=("the decoders disagree: %d different flag-format values, none asserted: "
                                   % len(flags) + "; ".join(notes_out) + tail + more))
    if analysed == 0:
        return SolverResult(status="blocked", evidence=evidence, engine=_ENGINE,
                            notes="no handout ELF could be loaded: " + "; ".join(skipped))
    if not found and guard_blocked:
        reason = getattr(getattr(ni, "_ne", None), "UNICORN_UNAVAILABLE_REASON", None) or "host guard"
        return SolverResult(status="blocked", evidence=evidence, engine=_ENGINE,
                            notes=("%d bound decoder call(s) could not be emulated: Unicorn is off on this host "
                                   "(%s) and the bounded x86-64 evaluator does not cover them" % (guard_blocked, reason)
                                   + tail + more))
    if found:
        return SolverResult(status="unsure", evidence=evidence, engine=_ENGINE,
                            notes=("emulated %d bound call(s); no output is in the flag format (outputs in the "
                                   "evidence)" % evaluated + tail + more))
    if lead_ev:
        return SolverResult(status="unsure", evidence=evidence, engine=_ENGINE,
                            notes=("no decoder was evaluated to an output; ranked candidate(s) in the evidence "
                                   "need an argument or an agent" + tail + more))
    if problems:
        return SolverResult(status="unsure", evidence=evidence, engine=_ENGINE,
                            notes="nothing decoder-like found, but the analysis did not complete" + tail + more)
    return SolverResult(status="none", evidence=evidence, engine=_ENGINE,
                        notes="every handout ELF was analysed; no decoder candidate was found" + more)


if __name__ == "__main__":            # manual: python solvers/binary/decoder_discovery.py <elf>
    import json
    m = analyse(Path(sys.argv[1]).read_bytes())
    rows = rank(m, (), check_leads(m))
    print(json.dumps([{"func": c.name, "addr": hex(c.addr), "score": c.score, "reasons": list(c.reasons),
                       "arity": c.func.arity, "bindings": [_fmt_args(b.args) + " " + b.source for b in c.bindings],
                       "unbound": c.unbound} for c in rows[:24]], indent=2))
