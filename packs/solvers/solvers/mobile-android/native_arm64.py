"""Straight-line AArch64 (arm64) JNI-transform emulator -- Day-24 look-ahead for the Mobile
`analysis` / computed-codec theme.

WHY THIS FILE EXISTS
--------------------
Day 23 ("Hook, Line, and Signal") shipped codec `analysis`: the `ANS-` code is COMPUTED by running the
app's own Dalvik method chain, and when the chain calls a `static native (J)J` JNI method the transform
lives in a bundled `.so`. `dex_chain_codec._emulate_x86` emulates that transform -- but ONLY for x86-64
(`capstone` `CS_MODE_64`). Real Android ships arm64 (`arm64-v8a`) libraries, so the single most likely
Day-24 escalation of this theme is an `.so` whose JNI transform is AArch64 machine code. Today
`dex_chain_codec._parse_so` keeps the symbols of ANY ELF64 (it never checks `e_machine`), so an arm64
transform is fed to the x86 disassembler, declines on the first unknown mnemonic, and the WHOLE chain goes
unsure/`:partial` or `None` (Day 23 was a 27-min live scramble for exactly this class of "we can't run the
transform" miss). Both the Day-23 retro forecast ("Escalations: native arm64/thumb ...") and
`docs/retro/ctf-solver-gap-analysis.md` ("arm64/aarch64 native disassembly for `.so`") flag this as the
confirmed gap (ticket T4 of `docs/retro/day24plus-buildplan-mobile.md`).

This module is the never-wrong arm64 counterpart of `_emulate_x86`: a straight-line emulator of the
integer data-processing subset a JNI `(J)J` code transform uses, matched to the same ABI contract (third
integer argument carries the `jlong`, result in the return register).

NEVER-WRONG CONTRACT
--------------------
The caller only ACCEPTS a value when it `fullmatch`es `ANS-[0-9A-F]{16}` out of a run (see
`dex_chain_codec.codes_in_dex_ex`), and a single code beside ANY decline is made UNSURE, never plain. So
the one and only danger is computing a WRONG 64-bit result that still fullmatches. This emulator is built
to make that impossible:

  * It models ONLY instructions whose integer semantics are exactly reproduced here (cross-checked against a
    Python reference in `tests/test_day24_native_arm64.py`). Everything else -- any branch (except `ret`,
    which stops), any memory access, any flag-setting / conditional / FP / SIMD / system instruction, any
    extend or bitfield form not listed -- raises `Decline`.
  * A `Decline` propagates exactly as `dex_chain_codec._emulate_x86`'s `_Decline` does: the VM's run loop
    counts it and the lone code becomes unsure. So a mis-modeled or unknown instruction can NEVER yield a
    plain wrong answer; it can only make the read unsure/None.
  * It fails closed on INDETERMINATE INPUT: only `x2` (the `jlong` argument), `xzr`/`wzr` (always 0) are
    defined on entry. Reading any other register before it has been written in this function declines -- so
    a transform that depends on the JNIEnv pointer, the jclass, or a stack slot (none of which are
    reproducible) is never "solved" to a fabricated code.
  * It requires an explicit `ret` to return a result. If the instruction stream ends or hits an
    undecodable byte before a `ret`, it declines (stricter than `_emulate_x86`, which would return a
    partial register value).

WIRING (left to the integrator; do NOT edit the shipped reader here)
--------------------------------------------------------------------
One dispatch point in `dex_chain_codec.VM._invoke`, the native branch (currently the single line
`return _emulate_x86(codeb, (args[0] if args else 0) & M64) & M64`). The `.so`'s architecture is known at
parse time, so route AArch64 functions here, x86-64 to `_emulate_x86`, e.g.:

    import native_arm64                                          # top of dex_chain_codec.py
    # in codes_in_dex_ex, beside `native_syms.update(_parse_so(...))`:
    arm_syms.update(native_arm64.aarch64_functions(bytes(sob)))  # same extraction, aarch64 ELFs only
    # in VM._invoke, the native branch:
    if sym in self.native_arm:                                  # an aarch64 JNI transform
        return native_arm64.emulate(codeb, (args[0] if args else 0) & M64) & M64
    return _emulate_x86(codeb, (args[0] if args else 0) & M64) & M64

`aarch64_functions` returns `{symbol: code_bytes}` for the FUNC symbols of an arm64 ELF64 only (empty for
any other machine or a non-ELF), using the same symbol walk as `_parse_so`, so an x86 `.so` is untouched
and routing stays exclusive by architecture. `Decline` need not be caught: `VM.run`'s `except
BaseException` already counts any exception from `_invoke` as a decline.
"""

import struct

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

EM_AARCH64 = 183  # ELF e_machine for AArch64 (0xB7)

MAX_INSNS = 100_000  # a straight-line function is bounded by its own size; a hard cap against pathology


class Decline(Exception):
    """Raised for anything this emulator does not model exactly. Counted by the caller as a decline;
    never turned into an answer. See the never-wrong contract in the module docstring."""


# --------------------------------------------------------------------------- ELF symbol extraction
def elf_machine(data):
    """e_machine of an ELF64 little-endian object, or None when `data` is not one."""
    try:
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:  # ELF64, little-endian
            return None
        return struct.unpack_from("<H", data, 0x12)[0]
    except Exception:
        return None


def aarch64_functions(data):
    """{symbol_name: machine_code_bytes} for the FUNC symbols of an AArch64 ELF64 shared object.

    Mirrors `dex_chain_codec._parse_so` (same section/symbol walk) but returns a map ONLY for an AArch64
    object; `{}` for any other machine or a malformed/non-ELF input, so an x86 `.so` is never routed here.
    """
    out = {}
    try:
        if elf_machine(data) != EM_AARCH64:
            return out
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
        secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from("<I", data, o + 4)[0]
            sh_addr = struct.unpack_from("<Q", data, o + 16)[0]
            sh_offset = struct.unpack_from("<Q", data, o + 24)[0]
            sh_size = struct.unpack_from("<Q", data, o + 32)[0]
            sh_link = struct.unpack_from("<I", data, o + 40)[0]
            sh_entsize = struct.unpack_from("<Q", data, o + 56)[0]
            secs.append((sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))

        def v2off(v):
            for (_t, a, off, sz, _l, _e) in secs:
                if a and a <= v < a + sz:
                    return off + (v - a)
            return None

        for (sh_type, _a, sh_offset, sh_size, sh_link, sh_entsize) in secs:
            if sh_type not in (11, 2):  # DYNSYM, SYMTAB
                continue
            if sh_link >= len(secs):
                continue
            stroff = secs[sh_link][2]
            ent = sh_entsize or 24
            for p in range(sh_offset, sh_offset + sh_size, ent):
                st_name = struct.unpack_from("<I", data, p)[0]
                st_info = data[p + 4]
                st_value = struct.unpack_from("<Q", data, p + 8)[0]
                st_size = struct.unpack_from("<Q", data, p + 16)[0]
                if (st_info & 0xF) != 2 or not st_size:  # STT_FUNC with a size
                    continue
                end = data.index(b"\x00", stroff + st_name)
                nm = data[stroff + st_name:end].decode("latin1")
                fo = v2off(st_value)
                if fo is not None:
                    out[nm] = data[fo:fo + st_size]
    except Exception:
        return {}
    return out


# --------------------------------------------------------------------------- the emulator
def _sign(val, bits):
    val &= (1 << bits) - 1
    if val >> (bits - 1):
        val -= (1 << bits)
    return val


class _State:
    """A straight-line AArch64 integer machine. Only x2 (the jlong arg), xzr/wzr are defined on entry;
    reading any other register before it is written declines (indeterminate -> never a fabricated code)."""

    def __init__(self, arg):
        self.reg = {"x2": arg & M64}          # jlong argument (3rd integer arg, AAPCS64)
        self.defined = {"x2"}                 # xzr/wzr handled explicitly in rd/wr

    @staticmethod
    def parse(name):
        """(canonical x-name, width_bits, is_zero) for an operand register name."""
        n = name.lower()
        if n in ("xzr", "wzr"):
            return None, (64 if n == "xzr" else 32), True
        if n in ("sp", "wsp"):                # a stack pointer value is indeterminate for a pure transform
            return "sp", (64 if n == "sp" else 32), False
        if n == "lr":
            return "x30", 64, False
        if n == "fp":
            return "x29", 64, False
        if n and n[0] == "x" and n[1:].isdigit():
            return "x" + n[1:], 64, False
        if n and n[0] == "w" and n[1:].isdigit():
            return "x" + n[1:], 32, False
        raise Decline("register %s" % name)

    def rd(self, name):
        canon, width, is_zero = self.parse(name)
        if is_zero:
            return 0
        if canon not in self.defined:
            # x0=JNIEnv*, x1=jclass, sp, scratch: indeterminate on entry. Fail closed.
            raise Decline("read before write: %s" % name)
        v = self.reg.get(canon, 0)
        return (v & M32) if width == 32 else (v & M64)

    def wr(self, name, val):
        canon, width, is_zero = self.parse(name)
        if is_zero:
            return
        self.reg[canon] = (val & M32) if width == 32 else (val & M64)  # 32-bit write zero-extends
        self.defined.add(canon)


def _width(state, regname):
    _c, w, _z = state.parse(regname)
    return w


def _apply_shift(val, sft_type, amount, width):
    """A shifted-register operand value (LSL/LSR/ASR/ROR), evaluated at the operand width."""
    from capstone import arm64
    mask = M64 if width == 64 else M32
    val &= mask
    if sft_type == arm64.ARM64_SFT_INVALID or amount == 0:
        return val
    amount &= (width - 1)
    if amount == 0:
        return val
    if sft_type == arm64.ARM64_SFT_LSL:
        return (val << amount) & mask
    if sft_type == arm64.ARM64_SFT_LSR:
        return val >> amount
    if sft_type == arm64.ARM64_SFT_ASR:
        return (_sign(val, width) >> amount) & mask
    if sft_type == arm64.ARM64_SFT_ROR:
        return ((val >> amount) | (val << (width - amount))) & mask
    raise Decline("shift type %s" % sft_type)


def _apply_extend(val, ext, amount, width):
    """An extended-register operand (uxt?/sxt?) for add/sub, then an optional left shift (0..4)."""
    from capstone import arm64
    mask = M64 if width == 64 else M32
    table = {
        arm64.ARM64_EXT_UXTB: (8, False), arm64.ARM64_EXT_UXTH: (16, False),
        arm64.ARM64_EXT_UXTW: (32, False), arm64.ARM64_EXT_UXTX: (64, False),
        arm64.ARM64_EXT_SXTB: (8, True), arm64.ARM64_EXT_SXTH: (16, True),
        arm64.ARM64_EXT_SXTW: (32, True), arm64.ARM64_EXT_SXTX: (64, True),
    }
    if ext not in table:
        raise Decline("extend %s" % ext)
    bits, signed = table[ext]
    val &= (1 << bits) - 1
    if signed:
        val = _sign(val, bits)
    if amount:
        if amount > 4:
            raise Decline("extend shift %d" % amount)
        val <<= amount
    return val & mask


def _operand(state, op, ins, width):
    """The integer value of a source operand (register with optional shift/extend, or an immediate)."""
    from capstone import arm64
    if op.type == arm64.ARM64_OP_IMM:
        v = op.imm & M64
        if op.shift.type != arm64.ARM64_SFT_INVALID:  # e.g. add x,x,#imm,lsl #12
            if op.shift.type != arm64.ARM64_SFT_LSL:
                raise Decline("imm shift type")
            v = (v << op.shift.value) & M64
        return v
    if op.type == arm64.ARM64_OP_REG:
        rname = ins.reg_name(op.reg)
        v = state.rd(rname)
        owidth = _width(state, rname)
        if op.ext not in (arm64.ARM64_EXT_INVALID, None):
            return _apply_extend(v, op.ext, op.shift.value, width)
        if op.shift.type != arm64.ARM64_SFT_INVALID:
            return _apply_shift(v, op.shift.type, op.shift.value, owidth)
        return v
    raise Decline("operand type %s" % op.type)


# mnemonics that write their first operand from a binary op on operands 2 and 3
_BIN = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "and": lambda a, b: a & b,
    "orr": lambda a, b: a | b,
    "eor": lambda a, b: a ^ b,
    "bic": lambda a, b: a & ~b,
    "orn": lambda a, b: a | ~b,
    "eon": lambda a, b: a ^ ~b,
    "mul": lambda a, b: a * b,
    "mneg": lambda a, b: -(a * b),
}
_SHIFT_VAR = {"lsl", "lsr", "asr", "ror"}  # 3-operand shift (immediate or register amount)
_UNARY = {"neg", "mvn"}
_EXT_1SRC = {"sxtb", "sxth", "sxtw", "uxtb", "uxth"}


def emulate(code, arg):
    """Run a straight-line AArch64 `(J)J` JNI transform on `arg`, returning the 64-bit result (the x0
    return register). Raises `Decline` on anything not exactly modeled (see the module docstring)."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    st = _State(arg)
    code = bytes(code)
    if not code:
        raise Decline("empty function")
    seen_ret = False
    count = 0

    for ins in md.disasm(code, 0):
        count += 1
        if count > MAX_INSNS:
            raise Decline("instruction cap")
        m = ins.mnemonic
        base = m.split(".")[0]
        ops = ins.operands

        if base == "ret":
            seen_ret = True
            break
        if base in ("nop", "hint"):
            continue

        # Any memory access: fail closed (a transform that reads/writes memory is not reproducible here).
        if any(o.type == arm64.ARM64_OP_MEM for o in ops):
            raise Decline("memory operand")

        w = _width(st, ins.reg_name(ops[0].reg)) if ops and ops[0].type == arm64.ARM64_OP_REG else 64
        mask = M64 if w == 64 else M32

        if base in _BIN:
            if len(ops) < 3:
                raise Decline("%s arity" % base)
            a = _operand(st, ops[1], ins, w)
            b = _operand(st, ops[2], ins, w)
            st.wr(ins.reg_name(ops[0].reg), _BIN[base](a & mask, b & mask) & mask)

        elif base in ("madd", "msub"):   # Rd = Ra +/- Rn*Rm
            n = _operand(st, ops[1], ins, w)
            k = _operand(st, ops[2], ins, w)
            ra = _operand(st, ops[3], ins, w)
            prod = (n * k) & mask
            st.wr(ins.reg_name(ops[0].reg), ((ra + prod) if base == "madd" else (ra - prod)) & mask)

        elif base in ("smull", "umull", "smulh", "umulh"):
            n = st.rd(ins.reg_name(ops[1].reg))
            k = st.rd(ins.reg_name(ops[2].reg))
            if base == "smull":
                st.wr(ins.reg_name(ops[0].reg), (_sign(n, 32) * _sign(k, 32)) & M64)
            elif base == "umull":
                st.wr(ins.reg_name(ops[0].reg), ((n & M32) * (k & M32)) & M64)
            elif base == "smulh":
                st.wr(ins.reg_name(ops[0].reg), ((_sign(n, 64) * _sign(k, 64)) >> 64) & M64)
            else:
                st.wr(ins.reg_name(ops[0].reg), (((n & M64) * (k & M64)) >> 64) & M64)

        elif base in _SHIFT_VAR:
            n = _operand(st, ops[1], ins, w)
            amt = _operand(st, ops[2], ins, w) & (w - 1)
            n &= mask
            if base == "lsl":
                res = (n << amt) & mask
            elif base == "lsr":
                res = n >> amt
            elif base == "asr":
                res = (_sign(n, w) >> amt) & mask
            else:  # ror
                res = ((n >> amt) | (n << (w - amt))) & mask if amt else n
            st.wr(ins.reg_name(ops[0].reg), res)

        elif base == "extr":   # Rd = (concat(Rn,Rm) >> lsb)[w bits]; ror alias has Rn==Rm
            n = st.rd(ins.reg_name(ops[1].reg)) & mask
            k = st.rd(ins.reg_name(ops[2].reg)) & mask
            lsb = ops[3].imm & (w - 1)
            res = ((n << w) | k) >> lsb
            st.wr(ins.reg_name(ops[0].reg), res & mask)

        elif base in ("mov", "movz"):            # movz-as-mov, and register mov
            st.wr(ins.reg_name(ops[0].reg), _operand(st, ops[1], ins, w) & mask)

        elif base == "movn":
            st.wr(ins.reg_name(ops[0].reg), (~_operand(st, ops[1], ins, w)) & mask)

        elif base == "movk":                     # insert imm16 at its shift, keep the rest (reads Rd)
            cur = st.rd(ins.reg_name(ops[0].reg))
            imm = ops[1].imm & 0xFFFF
            pos = ops[1].shift.value if ops[1].shift.type != arm64.ARM64_SFT_INVALID else 0
            st.wr(ins.reg_name(ops[0].reg), ((cur & ~(0xFFFF << pos)) | (imm << pos)) & mask)

        elif base in _UNARY:
            v = _operand(st, ops[1], ins, w) & mask
            st.wr(ins.reg_name(ops[0].reg), ((-v) if base == "neg" else (~v)) & mask)

        elif base in _EXT_1SRC:                  # sxtw x,w / uxtb w,w / ...
            src = st.rd(ins.reg_name(ops[1].reg))
            bits = {"b": 8, "h": 16, "w": 32}[base[3]]
            val = src & ((1 << bits) - 1)
            if base[0] == "s":
                val = _sign(val, bits)
            st.wr(ins.reg_name(ops[0].reg), val & mask)

        elif base in ("ubfx", "sbfx"):           # Rd = bits[lsb +: width] of Rn (zero/sign extended)
            n = st.rd(ins.reg_name(ops[1].reg)) & mask
            lsb = ops[2].imm
            width = ops[3].imm
            field = (n >> lsb) & ((1 << width) - 1)
            if base == "sbfx":
                field = _sign(field, width) & mask
            st.wr(ins.reg_name(ops[0].reg), field & mask)

        elif base == "clz":
            n = st.rd(ins.reg_name(ops[1].reg)) & mask
            st.wr(ins.reg_name(ops[0].reg), (w if n == 0 else (w - n.bit_length())))

        elif base == "rbit":
            n = st.rd(ins.reg_name(ops[1].reg)) & mask
            st.wr(ins.reg_name(ops[0].reg), int(format(n, "0%db" % w)[::-1], 2))

        elif base in ("rev", "rev16", "rev32", "rev64"):
            n = st.rd(ins.reg_name(ops[1].reg)) & mask
            nbytes = w // 8
            raw = n.to_bytes(nbytes, "little")
            if base == "rev" or base == "rev64":
                res = int.from_bytes(raw[::-1], "little")
            else:
                group = {"rev16": 2, "rev32": 4}[base]
                res = int.from_bytes(
                    b"".join(raw[i:i + group][::-1] for i in range(0, nbytes, group)), "little")
            st.wr(ins.reg_name(ops[0].reg), res & mask)

        else:
            raise Decline("mnemonic %s" % m)

    if not seen_ret:
        raise Decline("no ret reached")
    return st.reg.get("x0", 0) & M64
