#!/usr/bin/env python3
"""Decompile + invert byte-compare / mixer / per-char checks (B-026).

The reverse lane kept meeting the same crackme shape: a check reads the input, runs each byte (or a
fixed-width word) through a transform, and compares the result to a constant table.  Those were
inverted BY HAND, one challenge at a time.  This engine inverts the three recurring families with z3
(``solvers/toolkits/symbolic.py``, z3 5.1.0 in ``.venv``) and NEVER by matching a magic constant --
the multipliers, tables and per-index coefficients are inputs, so a custom mixer inverts exactly as a
textbook one does.

Three inversion primitives, each proven never-wrong (a value crosses to ``plain`` only when z3 has
proved it the unique satisfying input, or -- for the bijective mixer -- only after the recovered input
re-runs the forward transform to the given output):

  * :func:`invert_per_byte`  -- a per-byte transform ``f(s[i], i) == T[i]`` with INDEX-DEPENDENT
    coefficients (``((s[i]^0x5d) + 7*i + 0x0b) & 0xff == T[i]``, ``rol8(s[i], (1+3i)&7) + key[i&7]``).
    Each position's forward ops are expressed over the symbolic input byte and z3 recovers the bytes.
  * :func:`invert_positions` -- a per-POSITION check solver (the JVM / bytecode ``charAt``-indexed
    block shape): each position's predicate is solved on its own byte domain and must have exactly one
    solution, so the key is assembled only when every position is uniquely pinned.
  * :func:`invert_mixer`     -- a fixed-width invertible mixer (xorshift / multiply / rotate, e.g. a
    murmur ``fmix64`` with custom odd multipliers).  Inverted algebraically (modular inverse +
    xorshift self-inverse) and VERIFIED by re-applying the forward transform.

And an automated no-model pass for native ELFs:

  * :func:`invert_elf_straightline` lifts STRAIGHT-LINE x86/x86-64 check functions (via
    ``symbolic.lift_linear`` over each function's own code extent) over a bounded sweep of candidate
    functions and input lengths, recovering the accepted input with a z3 uniqueness proof.  The
    decompile artefacts B-011 wrote to ``recon/decompile/`` are cited as evidence when present.
  * :func:`invert_mixer_check` / :func:`recognise_mixer_function` read a WORD-MIXER check's structure
    from x86 code (an exact expression-tree interpreter, forward branches explored, calls to a
    recognised mixer function inlined), rewrite each compare into a mixer op list and invert it with
    :func:`invert_mixer`; the input is reported only when every byte read is pinned by a bijection and
    every lifted constraint re-evaluates true on it.
  * :func:`invert_jvm_class` reads a Java class file (never loaded), decodes each ``check(String)``-like
    method with ``bytecode_lifters.lift_jvm_code`` and emulates the 32-bit int stack over the input's
    characters; the accepted path feeds :func:`invert_positions` (or one joint z3 solve).
  * :func:`solve` is the engine entry (``run = "challenge"``).  It runs these passes under a
    whole-run time budget and reports the recovered input: ``candidate`` when the input itself is in
    the event flag format, else ``unsure`` with the recovered bytes in the notes/evidence for the agent
    (the flag is often DERIVED from the key, e.g. a keyed generator, which a model/agent finishes).
    Errors, skipped files (unsupported arch, too large, unparseable) and an exhausted budget are named
    in the notes; ``none`` means every handout file was analysed and nothing proved unique.

NOTHING here executes a challenge binary.  The ELF is read statically; the lift models instructions
symbolically; the transforms are pure arithmetic.  Verification is a z3 proof or a forward re-apply,
never a run.  (Running the candidate against the real checker in the networkless sandbox is a separate,
deliberate, event-time step -- see the build log.)
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"

# symbolic.py (the z3 engine) lives in the toolkits lane; its basename is unique, so a flat import is
# unambiguous once the lane is on sys.path (it always is under the engine boot and the test conftest).
if str(TOOLKITS) not in sys.path:
    sys.path.insert(1, str(TOOLKITS))

try:
    import symbolic  # noqa: E402  (flat import on the engine sys.path)
except Exception as exc:  # noqa: BLE001
    raise RuntimeError(
        "invert_checks needs solvers/toolkits/symbolic.py (z3 engine); it was not importable: "
        f"{exc}"
    ) from exc


# ----------------------------------------------------------------------------- bounds (hard caps)
MAX_LEN = symbolic.MAX_BYTES          # input bytes in one per-byte / per-position solve
MAX_OPS = 256                         # transform ops in one pipeline
MAX_WIDTH = 256                       # bit-width of a mixer word / a per-byte cell
DEFAULT_TIMEOUT_MS = symbolic.DEFAULT_TIMEOUT_MS
MAX_ELF_BYTES = 64 * 1024 * 1024      # a file larger than this is not lifted (= pwn.read_elf's cap)
MAX_HANDOUT_FILES = 8                 # ELF / class files tried by solve(); the rest are named, not tried
MAX_ELF_FUNCS = 24                    # candidate check functions tried in one ELF
MAX_ELF_LENGTHS = 24                  # input lengths swept per function
# Common accepted-input lengths, tried when the caller gives no explicit sweep (keys, passwords).
DEFAULT_LENGTHS = (4, 5, 6, 8, 10, 12, 14, 16, 20, 24, 32)

_BYTE_OPS = frozenset({"xor", "add", "sub", "mul", "rol", "ror"})
_MIX_OPS = frozenset({"xor", "add", "sub", "mul", "xorshift_right", "xorshift_left", "rotl", "rotr"})


class InvertError(ValueError):
    """A malformed transform / operand (loud, named; never a silent empty result)."""


# ============================================================ per-byte index-dependent transform

def _coeff(operand, index: int) -> int:
    """The concrete operand value a transform op uses at position ``index``.

    ``operand`` is one of:
      * an ``int``                              -- a constant for every position;
      * a ``bytes``/``list``/``tuple`` of ints  -- a full-length table, value ``operand[index]``;
      * a ``dict`` ``{"i_mul":a,"i_add":b,"mask":m}``  -- ``(a*index + b)`` then ``& m`` when ``m`` is
        given (``(1+3*i)&7``);
      * a ``dict`` ``{"table":[...],"mask":m}``        -- ``table[index & m]`` (``key[i&7]``), or
        ``table[index % len(table)]`` when no mask.
    """
    if isinstance(operand, bool):
        raise InvertError("operand must not be a bool")
    if isinstance(operand, int):
        return operand
    if isinstance(operand, (bytes, bytearray, list, tuple)):
        if not 0 <= index < len(operand):
            raise InvertError(f"table operand has no entry for index {index} (len {len(operand)})")
        v = operand[index]
        if isinstance(v, bool) or not isinstance(v, int):
            raise InvertError("table operand must hold ints")
        return v
    if isinstance(operand, dict):
        mask = operand.get("mask")
        if mask is not None and (isinstance(mask, bool) or not isinstance(mask, int) or mask < 0):
            raise InvertError("operand mask must be a non-negative int")
        if "table" in operand:
            tbl = operand["table"]
            if not isinstance(tbl, (bytes, bytearray, list, tuple)) or not tbl:
                raise InvertError("operand table must be a non-empty sequence")
            idx = (index & mask) if mask is not None else (index % len(tbl))
            if not 0 <= idx < len(tbl):
                raise InvertError(f"operand table index {idx} out of range (len {len(tbl)})")
            v = tbl[idx]
            if isinstance(v, bool) or not isinstance(v, int):
                raise InvertError("operand table must hold ints")
            return v
        unknown = set(operand) - {"i_mul", "i_add", "mask"}
        if unknown:
            raise InvertError(f"operand has unknown keys {sorted(unknown)}")
        i_mul = operand.get("i_mul", 0)
        i_add = operand.get("i_add", 0)
        for nm, val in (("i_mul", i_mul), ("i_add", i_add)):
            if isinstance(val, bool) or not isinstance(val, int):
                raise InvertError(f"operand {nm} must be an int")
        val = index * i_mul + i_add
        return (val & mask) if mask is not None else val
    raise InvertError(f"unsupported operand {operand!r}")


def _check_ops(ops, allowed, label: str):
    if not isinstance(ops, (list, tuple)) or isinstance(ops, (str, bytes)):
        raise InvertError(f"{label} must be a list of (op, operand) pairs")
    if not 1 <= len(ops) <= MAX_OPS:
        raise InvertError(f"{label} must have 1..{MAX_OPS} ops (got {len(ops)})")
    out = []
    for item in ops:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise InvertError(f"{label} op must be a (name, operand) pair, got {item!r}")
        name, operand = item
        if name not in allowed:
            raise InvertError(f"{label} op {name!r} is not one of {sorted(allowed)}")
        out.append((name, operand))
    return out


def _rotl(value: int, count: int, width: int) -> int:
    count %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value << count) | (value >> (width - count))) & mask if count else value


def _rotr(value: int, count: int, width: int) -> int:
    return _rotl(value, width - (count % width), width)


def apply_byte_ops(value: int, index: int, ops, *, width: int = 8) -> int:
    """Forward reference: run one byte ``value`` at ``index`` through ``ops`` modulo ``2**width``.

    The forward transform the check applies; :func:`invert_per_byte` recovers ``value`` from the
    target.  Kept in lock-step with the z3 builder so a round-trip (forward then invert) is a real
    test of both.
    """
    ops = _check_ops(ops, _BYTE_OPS, "ops")
    _width(width)
    mask = (1 << width) - 1
    v = value & mask
    for name, operand in ops:
        k = _coeff(operand, index) & mask if name in ("xor", "add", "sub", "mul") else _coeff(operand, index)
        if name == "xor":
            v ^= k
        elif name == "add":
            v = (v + k) & mask
        elif name == "sub":
            v = (v - k) & mask
        elif name == "mul":
            v = (v * k) & mask
        elif name == "rol":
            v = _rotl(v, k, width)
        else:  # ror
            v = _rotr(v, k, width)
    return v & mask


def _width(width: int) -> int:
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= MAX_WIDTH:
        raise InvertError(f"width must be an int in 1..{MAX_WIDTH}")
    return width


def _z3_apply_byte_ops(z3, x, index: int, ops, width: int):
    v = x
    for name, operand in ops:
        k = _coeff(operand, index)
        if name == "xor":
            v = v ^ z3.BitVecVal(k, width)
        elif name == "add":
            v = v + z3.BitVecVal(k, width)
        elif name == "sub":
            v = v - z3.BitVecVal(k, width)
        elif name == "mul":
            v = v * z3.BitVecVal(k, width)
        elif name == "rol":
            v = z3.RotateLeft(v, k % width)
        else:  # ror
            v = z3.RotateRight(v, k % width)
    return v


def invert_per_byte(targets, ops, *, charset=None, width: int = 8,
                    timeout_ms: int = DEFAULT_TIMEOUT_MS, max_candidates=None):
    """Recover the input bytes ``s`` whose per-byte transform hits ``targets``, never-wrong.

    For every position ``i``, assert ``apply_ops(s[i], i) == targets[i]`` (modulo ``2**width``) over a
    fresh symbolic cell, add the optional ``charset`` and let z3 prove uniqueness.  Returns a
    :class:`symbolic.Solution`: ``UNIQUE`` -> :meth:`plain` is ``bytes`` (``width == 8``) or the model
    dict; ``MULTIPLE`` -> bounded unsure candidates; underconstrained / unsat / timeout -> ``None``.

    ``targets``   the expected output table (``bytes`` or a list of ints), one per input byte.
    ``ops``       the forward ops, a list of ``(name, operand)`` pairs applied left to right.  Names:
                  ``xor add sub mul`` (modular) and ``rol ror`` (rotate by ``operand & (width-1)``).
                  ``operand`` is a constant, a per-index table, or an index expression (see
                  :func:`_coeff`): this is how an INDEX-DEPENDENT check is inverted with no signature.
    """
    z3 = symbolic._require_z3()
    ops = _check_ops(ops, _BYTE_OPS, "ops")
    width = _width(width)
    tgt = _targets(targets, width)
    n = len(tgt)
    if not 1 <= n <= MAX_LEN:
        raise InvertError(f"targets length {n} out of range 1..{MAX_LEN}")
    names = [f"in{i}" for i in range(n)]
    xs = [z3.BitVec(names[i], width) for i in range(n)]
    cons = [_z3_apply_byte_ops(z3, xs[i], i, ops, width) == z3.BitVecVal(tgt[i], width)
            for i in range(n)]
    if charset is not None:
        cons = cons + symbolic.charset_constraints(xs, charset)
    mc = symbolic.MAX_CANDIDATES if max_candidates is None else max_candidates
    return symbolic.solve(xs, cons, timeout_ms=timeout_ms, max_candidates=mc,
                          byte_bits=(width if width == 8 else None), var_names=names)


def _targets(targets, width: int):
    if isinstance(targets, (bytes, bytearray)):
        vals = list(targets)
    elif isinstance(targets, (list, tuple)):
        vals = list(targets)
    else:
        raise InvertError("targets must be bytes or a list of ints")
    top = (1 << width) - 1
    out = []
    for v in vals:
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= top:
            raise InvertError(f"target {v!r} is not a value in 0..{top}")
        out.append(v)
    return out


# ============================================================ per-position uniqueness search

def invert_positions(n: int, check_pos, *, charset=None, width: int = 8,
                     timeout_ms: int = DEFAULT_TIMEOUT_MS):
    """Solve a per-POSITION check: each position is an independent single-byte problem.

    ``check_pos(i, x)`` returns the z3 constraint(s) (a ``BoolRef`` or an iterable) that position ``i``
    places on its symbolic byte ``x`` (a fresh ``BitVec(width)``).  Each position is solved on its own
    and must be UNIQUE; the key is assembled (and :meth:`Solution.plain` returns the bytes) only when
    every position is uniquely pinned.  This is the lifted-bytecode / ``charAt``-block shape: brute one
    position at a time, each with a uniqueness proof.

    If any position has several models, no model, or times out, the result is NOT unique: its status
    is the worst position's and :meth:`plain` is ``None``, with the ambiguous positions named in
    ``detail``.
    """
    z3 = symbolic._require_z3()
    width = _width(width)
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_LEN:
        raise InvertError(f"n must be an int in 1..{MAX_LEN}")
    if not callable(check_pos):
        raise InvertError("check_pos must be callable(index, x) -> constraints")
    names = [f"in{i}" for i in range(n)]
    assembled = {}
    bad = []                       # (index, status) for positions that are not unique
    worst = symbolic.UNIQUE
    rank = {symbolic.UNIQUE: 0, symbolic.MULTIPLE: 1, symbolic.UNDERCONSTRAINED: 2,
            symbolic.UNSAT: 3, symbolic.TIMEOUT: 4, symbolic.ERROR: 5, symbolic.PARTIAL: 5}
    for i in range(n):
        x = z3.BitVec(names[i], width)
        cons = symbolic._as_list(check_pos(i, x))
        if charset is not None:
            cons = cons + symbolic.charset_constraints([x], charset)
        sol = symbolic.solve([x], cons, timeout_ms=timeout_ms, var_names=[names[i]])
        if sol.status == symbolic.UNIQUE:
            assembled[names[i]] = sol.models[0][names[i]]
        else:
            bad.append((i, sol.status))
            if rank.get(sol.status, 5) > rank.get(worst, 0):
                worst = sol.status
    if not bad:
        detail = f"every one of the {n} positions had exactly one solution (z3-proved)"
        return symbolic.Solution(symbolic.UNIQUE, [assembled], names,
                                 byte_bits=(width if width == 8 else None), detail=detail)
    detail = ("not unique: " +
              ", ".join(f"pos {i} {st}" for i, st in bad[:16]) +
              (f", and {len(bad) - 16} more" if len(bad) > 16 else ""))
    return symbolic.Solution(worst, [], names, byte_bits=(width if width == 8 else None),
                             detail=detail, reason=f"{len(bad)} position(s) not uniquely pinned")


# ============================================================ fixed-width invertible mixer

def _modinv_pow2(m: int, width: int) -> int:
    """The modular inverse of an odd ``m`` modulo ``2**width`` (raises on an even m)."""
    if m % 2 == 0:
        raise InvertError(f"multiplier {m:#x} is even, so it is not invertible modulo 2**{width}")
    return pow(m & ((1 << width) - 1), -1, 1 << width)


def inv_rshift_xor(y: int, shift: int, width: int) -> int:
    """Invert ``x ^= x >> shift`` over ``width`` bits: recover ``x`` from ``y = x ^ (x >> shift)``.

    ``y ^ (x >> shift)`` is a contraction whose fixed point is the inverse; starting from ``y`` it is
    exact after ``ceil(width/shift)`` steps (each pass fixes the next ``shift`` high bits)."""
    if shift <= 0 or shift >= width:
        raise InvertError(f"xorshift_right amount {shift} must be in 1..{width - 1}")
    mask = (1 << width) - 1
    y &= mask
    x = y
    for _ in range((width + shift - 1) // shift):
        x = (y ^ (x >> shift)) & mask
    return x


def inv_lshift_xor(y: int, shift: int, width: int) -> int:
    """Invert ``x ^= x << shift`` over ``width`` bits (the low-bit-first mirror of
    :func:`inv_rshift_xor`)."""
    if shift <= 0 or shift >= width:
        raise InvertError(f"xorshift_left amount {shift} must be in 1..{width - 1}")
    mask = (1 << width) - 1
    y &= mask
    x = y
    for _ in range((width + shift - 1) // shift):
        x = (y ^ ((x << shift) & mask)) & mask
    return x


def apply_mixer(value: int, ops, *, width: int = 64) -> int:
    """Forward reference: run ``value`` through a fixed-width invertible mixer (``xorshift_right s``,
    ``xorshift_left s``, ``mul m`` (odd), ``xor c``, ``add c``, ``sub c``, ``rotl r``, ``rotr r``)."""
    ops = _check_ops(ops, _MIX_OPS, "ops")
    width = _width(width)
    mask = (1 << width) - 1
    v = value & mask
    for name, amt in ops:
        if isinstance(amt, bool) or not isinstance(amt, int):
            raise InvertError(f"mixer op {name} amount must be an int")
        if name == "mul":
            if amt % 2 == 0:
                raise InvertError(f"mul multiplier {amt:#x} is even (not invertible mod 2**{width})")
            v = (v * (amt & mask)) & mask
        elif name == "xor":
            v ^= amt & mask
        elif name == "add":
            v = (v + amt) & mask
        elif name == "sub":
            v = (v - amt) & mask
        elif name == "xorshift_right":
            if not 1 <= amt < width:
                raise InvertError(f"xorshift_right amount {amt} must be in 1..{width - 1}")
            v ^= v >> amt
        elif name == "xorshift_left":
            if not 1 <= amt < width:
                raise InvertError(f"xorshift_left amount {amt} must be in 1..{width - 1}")
            v = (v ^ (v << amt)) & mask
        elif name == "rotl":
            v = _rotl(v, amt, width)
        else:  # rotr
            v = _rotr(v, amt, width)
    return v & mask


def invert_mixer(output: int, ops, *, width: int = 64) -> int:
    """Recover the input word of a fixed-width invertible mixer from its ``output``, exactly.

    Each op is a bijection on ``2**width`` bits, so the composition inverts by undoing the ops in
    reverse (``mul`` by the modular inverse, each xorshift by its self-inverse, rotate the other way).
    The result is VERIFIED by re-applying the forward mixer -- the never-wrong boundary, and why a
    CUSTOM multiplier needs no signature.  Raises :class:`InvertError` on a non-invertible op.
    """
    ops = _check_ops(ops, _MIX_OPS, "ops")
    width = _width(width)
    mask = (1 << width) - 1
    if isinstance(output, bool) or not isinstance(output, int) or not 0 <= output <= mask:
        raise InvertError(f"output must be a value in 0..{mask}")
    v = output & mask
    for name, amt in reversed(ops):
        if isinstance(amt, bool) or not isinstance(amt, int):
            raise InvertError(f"mixer op {name} amount must be an int")
        if name == "mul":
            v = (v * _modinv_pow2(amt, width)) & mask
        elif name == "xor":
            v ^= amt & mask
        elif name == "add":
            v = (v - amt) & mask
        elif name == "sub":
            v = (v + amt) & mask
        elif name == "xorshift_right":
            v = inv_rshift_xor(v, amt, width)
        elif name == "xorshift_left":
            v = inv_lshift_xor(v, amt, width)
        elif name == "rotl":
            v = _rotr(v, amt, width)
        else:  # rotr
            v = _rotl(v, amt, width)
    if apply_mixer(v, ops, width=width) != (output & mask):
        # The op list is not a bijection as modelled (should be impossible for the allowed ops); fail
        # loudly rather than return a value the forward transform does not reproduce.
        raise InvertError("recovered input does not reproduce the output under the forward mixer")
    return v


# ============================================================ x86 word-mixer recogniser
#
# The uplink-denied / ground-lock shape: the key is read as fixed-width little-endian words, each word
# runs through an invertible mixer (xorshift / odd multiply / xor / add / rotate, e.g. a custom-multiplier
# fmix64), and the results are compared to constants.  The z3 lift cannot prove such a check (64-bit
# multiply chains), so this pass reads the code's STRUCTURE instead: a small exactly-modelled
# interpreter turns the straight-line code into expression trees over the input words, a matcher
# rewrites each "must be zero / must be equal" term into a mixer op list, and invert_mixer undoes it.
# No constant is matched against a signature: the multipliers, shifts and targets come out of the code.
#
# Never-wrong: an instruction, operand or memory access the interpreter does not model exactly makes
# the whole function "not a mixer check" (None).  A recovered input is accepted only when (1) every
# input byte the check reads lies in a word pinned by a bijective mixer equation (so the input is
# unique), and (2) every constraint the code imposes evaluates true on it (re-checked over the lifted
# trees with concrete arithmetic, independent of the matcher).

MAX_MIXER_INSNS = 2048                # instructions interpreted in one function (all paths together)
MAX_MIXER_PATHS = 64                  # paths through forward in-region branches
MAX_MIXER_SCAN = 512                  # functions of one ELF checked for being a mixer function
MAX_MIXER_FUNC_BYTES = 1024           # a function longer than this is not checked as a mixer


class _NotMixer(Exception):
    """The code is not (exactly) a mixer-and-compare shape; the reason names what was met."""


class _Rejected(_NotMixer):
    """This path returns a constant the success model rejects (a fail path)."""


def _wmask(w: int) -> int:
    return (1 << w) - 1


def _c(v: int, w: int):
    return ("c", w, v & _wmask(w))


_FOLD = {
    "xor": lambda a, b, m: a ^ b, "or": lambda a, b, m: a | b, "and": lambda a, b, m: a & b,
    "add": lambda a, b, m: (a + b) & m, "sub": lambda a, b, m: (a - b) & m,
    "mul": lambda a, b, m: (a * b) & m,
}


def _bin(op: str, w: int, a, b):
    """A width-``w`` binary node, constant-folded; pointer/stack markers never mix with arithmetic."""
    for x in (a, b):
        if x[0] in ("ptr", "sp"):
            raise _NotMixer(f"{op} on a pointer")
    if a[0] == "c" and b[0] == "c":
        return _c(_FOLD[op](a[2], b[2], _wmask(w)), w)
    if op in ("xor", "or", "add") and b[0] == "c" and b[2] == 0:
        return a
    if op in ("xor", "or", "add") and a[0] == "c" and a[2] == 0:
        return b
    if op == "sub" and b[0] == "c" and b[2] == 0:
        return a
    return (op, w, a, b)


def _shift(op: str, w: int, a, s: int):
    if a[0] in ("ptr", "sp"):
        raise _NotMixer(f"{op} on a pointer")
    s &= (63 if w == 64 else 31)
    if s == 0:
        return a
    if a[0] == "c":
        v, m = a[2], _wmask(w)
        if op == "shr":
            return _c(v >> s, w)
        if op == "shl":
            return _c(v << s, w)
        if op == "rol":
            return _c(_rotl(v, s, w), w)
        return _c(_rotr(v, s, w), w)
    if op in ("shr", "shl") and s >= w:
        return _c(0, w)
    return (op, w, a, s)


def _fit(node, w: int):
    """``node`` seen at width ``w``: truncated (low bits) or zero-extended."""
    if node is None:
        raise _NotMixer("read of an undefined register")
    if node[0] in ("ptr", "sp"):
        if w != node[1]:
            raise _NotMixer("partial-width use of a pointer")
        return node
    if node[0] == "merge":                      # low bits from a partial-register write
        if w <= node[3]:
            return _fit(node[4], w)
        if node[1] != w or node[2] is None:
            raise _NotMixer("a read across a partial-register write into an undefined value")
        return node
    if node[1] == w:
        return node
    if node[0] == "c":
        return _c(node[2], w)
    if node[1] > w:
        inner = node
        while inner[0] == "zx" and inner[2][1] >= w:      # zero-extension keeps the low bits
            inner = inner[2]
        return inner if inner[1] == w else ("lo", w, inner)
    return ("zx", w, node)


def _signed(v: int, w: int) -> int:
    return v - (1 << w) if v >> (w - 1) & 1 else v


def _apply_ops_nodes(x, ops, w: int):
    """Expression tree of mixer ``ops`` applied to node ``x`` (the shape the matcher reads back)."""
    for name, k in ops:
        if name == "xorshift_right":
            x = _bin("xor", w, x, _shift("shr", w, x, k))
        elif name == "xorshift_left":
            x = _bin("xor", w, x, _shift("shl", w, x, k))
        elif name == "rotl":
            x = _shift("rol", w, x, k)
        elif name == "rotr":
            x = _shift("ror", w, x, k)
        else:
            x = _bin(name, w, x, _c(k, w))
    return x


def _xor_leaves(node, out):
    if node[0] == "xor":
        _xor_leaves(node[2], out)
        _xor_leaves(node[3], out)
    else:
        out.append(node)


def _is_base(node) -> bool:
    return node[0] in ("ld", "arg") or (node[0] == "lo" and node[2][0] == "arg")


def _match_word(node, depth: int = 0):
    """``(base, ops)`` with ``node == apply_mixer(base, ops)`` over ``node``'s width, or None.

    Reads structure only: an n-ary XOR of one value ``u``, optionally ``u >> s`` / ``u << s`` (an
    xorshift), and constants; an odd multiply / add / sub by a constant; a rotate by a constant."""
    if depth > MAX_OPS:
        return None
    w = node[1]
    if _is_base(node):
        return node, []
    kind = node[0]
    if kind == "xor":
        leaves: list = []
        _xor_leaves(node, leaves)
        k = 0
        rest = []
        for lf in leaves:
            if lf[1] != w:
                return None
            if lf[0] == "c":
                k ^= lf[2]
            else:
                rest.append(lf)
        tail = [("xor", k)] if k else []
        if len(rest) == 1:
            inner = _match_word(rest[0], depth + 1)
            return None if inner is None else (inner[0], inner[1] + tail)
        if len(rest) == 2:
            for u, sh in ((rest[0], rest[1]), (rest[1], rest[0])):
                if sh[0] in ("shr", "shl") and sh[2] == u:
                    inner = _match_word(u, depth + 1)
                    if inner is None:
                        return None
                    step = ("xorshift_right" if sh[0] == "shr" else "xorshift_left", sh[3])
                    return inner[0], inner[1] + [step] + tail
        return None
    if kind in ("mul", "add"):
        a, b = node[2], node[3]
        if a[0] == "c":
            a, b = b, a
        if b[0] != "c" or a[1] != w:
            return None
        if kind == "mul" and b[2] % 2 == 0:
            return None                              # not a bijection: never pin through it
        inner = _match_word(a, depth + 1)
        return None if inner is None else (inner[0], inner[1] + [(kind, b[2])])
    if kind == "sub":
        a, b = node[2], node[3]
        if b[0] != "c" or a[1] != w:
            return None
        inner = _match_word(a, depth + 1)
        return None if inner is None else (inner[0], inner[1] + [("sub", b[2])])
    if kind in ("rol", "ror"):
        inner = _match_word(node[2], depth + 1)
        return None if inner is None else (inner[0], inner[1] + [("rotl" if kind == "rol" else "rotr",
                                                                   node[3])])
    return None


def _eval(node, inp: bytes, arg: int | None, memo: dict):
    """Concrete value of a lifted tree on input ``inp`` (the independent re-check)."""
    key = id(node)
    if key in memo:
        return memo[key]
    kind, w = node[0], node[1]
    m = _wmask(w) if isinstance(w, int) and w > 1 else 1
    if kind == "c":
        v = node[2]
    elif kind == "ld":
        off, nb = node[2], w // 8
        if off < 0 or off + nb > len(inp):
            raise _NotMixer(f"the check reads input bytes {off}..{off + nb - 1}, past the recovered key")
        v = int.from_bytes(inp[off:off + nb], "little")
    elif kind == "arg":
        if arg is None:
            raise _NotMixer("an argument word with no value")
        v = arg & m
    elif kind in _FOLD:
        v = _FOLD[kind](_eval(node[2], inp, arg, memo), _eval(node[3], inp, arg, memo), m) & m
    elif kind in ("shr", "shl", "rol", "ror"):
        x, s = _eval(node[2], inp, arg, memo), node[3]
        v = {"shr": lambda: x >> s, "shl": lambda: (x << s) & m, "rol": lambda: _rotl(x, s, w),
             "ror": lambda: _rotr(x, s, w)}[kind]()
    elif kind in ("zx", "lo"):
        v = _eval(node[2], inp, arg, memo) & m
    elif kind == "merge":
        if node[2] is None:
            raise _NotMixer("a value built on an undefined register")
        lowm = _wmask(node[3])
        v = (_eval(node[2], inp, arg, memo) & ~lowm & m) | _eval(node[4], inp, arg, memo)
    elif kind == "bool":
        v = _eval(node[2], inp, arg, memo)
    elif kind == "eq":
        v = int(_eval(node[2], inp, arg, memo) == _eval(node[3], inp, arg, memo))
    elif kind == "ne":
        v = int(_eval(node[2], inp, arg, memo) != _eval(node[3], inp, arg, memo))
    else:
        raise _NotMixer(f"cannot evaluate a {kind} node")
    memo[key] = v
    return v


def _loads(node, out: set, seen: set):
    if id(node) in seen:
        return
    seen.add(id(node))
    if node[0] == "ld":
        out.add((node[2], node[1] // 8))
        return
    for x in node[2:]:
        if isinstance(x, tuple):
            _loads(x, out, seen)


class _MixInterp:
    """Exact, bounded interpreter of one straight-line x86 region into expression trees.

    Registers hold trees (None = clobbered/undefined, which raises when read).  The input pointer is a
    ``("ptr", 64, off)`` marker; loads through it become ``("ld", bits, off)`` leaves.  Only the stack
    may be written.  A conditional branch out of the region is a check that must not be taken (the
    ``cmp; jne fail`` convention, as in ``symbolic.lift_linear``); any in-region branch, call (other than
    to a recognised mixer function), unmodelled instruction or memory access raises _NotMixer."""

    _CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")

    def __init__(self, word: int, lo: int, hi: int, resolver=None):
        self.word = word
        self.lo, self.hi = lo, hi
        self.regs: dict = {}
        self.stack: dict = {}                     # delta -> (size, node)
        self.flags = None
        self.cons: list = []                      # bool nodes that must hold on the accepted path
        self.resolver = resolver
        self.regs["rsp"] = ("sp", word, 0)

    # -- operands
    def reg_get(self, name: str):
        ent = symbolic._REGMAP.get(name)
        if ent is None:
            raise _NotMixer(f"register {name} is not modelled")
        canon, size, high = ent
        if high:
            raise _NotMixer(f"high-byte register {name}")
        v = self.regs.get(canon)
        if v is None:
            raise _NotMixer(f"read of undefined register {name}")
        return v if size * 8 == self.word else _fit(v, size * 8)

    def reg_set(self, name: str, val):
        ent = symbolic._REGMAP.get(name)
        if ent is None:
            raise _NotMixer(f"register {name} is not modelled")
        canon, size, high = ent
        if high:
            raise _NotMixer(f"high-byte register {name}")
        bits = size * 8
        if bits == self.word:
            self.regs[canon] = val
            return
        if bits == 32 and self.word == 64:          # a 32-bit write zero-extends into the 64-bit reg
            v32 = _fit(val, 32)
            self.regs[canon] = _c(v32[2], 64) if v32[0] == "c" else ("zx", 64, v32)
            return
        old = self.regs.get(canon)
        lowm = _wmask(bits)
        if old is not None and old[0] == "c":
            if val[0] == "c":
                self.regs[canon] = _c((old[2] & ~lowm) | (val[2] & lowm), self.word)
                return
            if old[2] & ~lowm == 0:
                self.regs[canon] = ("zx", self.word, _fit(val, bits))
                return
        # the low `bits` are now `val`; the rest are the old value's (readable only if it was defined)
        self.regs[canon] = ("merge", self.word, old, bits, _fit(val, bits))

    def addr(self, ins, op, x86):
        mem = op.mem
        if mem.segment != 0:
            raise _NotMixer("segment-relative memory")
        if mem.base == 0:
            raise _NotMixer("absolute memory (a data table) is not modelled")
        bname = ins.reg_name(mem.base)
        if bname in ("rip", "eip"):
            raise _NotMixer("rip-relative memory (a data table) is not modelled")
        b = self.reg_get(bname)
        disp = mem.disp
        if mem.index != 0:
            idx = self.reg_get(ins.reg_name(mem.index))
            if idx[0] != "c":
                raise _NotMixer("a symbolic memory index")
            disp += idx[2] * mem.scale
        if b[0] in ("ptr", "sp"):
            return (b[0], b[1], b[2] + disp)
        raise _NotMixer("memory through a non-pointer register")

    def read(self, ins, op, x86, size=None):
        size = size or op.size
        if op.type == x86.X86_OP_REG:
            return self.reg_get(ins.reg_name(op.reg))
        if op.type == x86.X86_OP_IMM:
            return _c(op.imm, size * 8)
        if op.type == x86.X86_OP_MEM:
            where = self.addr(ins, op, x86)
            if where[0] == "ptr":
                if where[2] < 0 or where[2] > MAX_LEN:
                    raise _NotMixer("input read out of range")
                return ("ld", size * 8, where[2])
            slot = self.stack.get(where[2])
            if slot is None or slot[0] != size or slot[1] is None:
                raise _NotMixer("read of an unwritten / mis-sized / opaque stack slot")
            return slot[1]
        raise _NotMixer("operand type not modelled")

    def write(self, ins, op, x86, val):
        if op.type == x86.X86_OP_REG:
            self.reg_set(ins.reg_name(op.reg), val)
            return
        if op.type == x86.X86_OP_MEM:
            where = self.addr(ins, op, x86)
            if where[0] != "sp":
                raise _NotMixer("a memory write outside the stack")
            self.stack[where[2]] = (op.size, val if val[0] in ("ptr", "sp") else _fit(val, op.size * 8))
            return
        raise _NotMixer("write to a non-register, non-memory operand")

    def zf_cond(self, negate: bool):
        f = self.flags
        if f is None:
            raise _NotMixer("a condition on undefined flags")
        if f[0] == "cmp":
            a, b = f[1], f[2]
        else:
            a, b = f[1], _c(0, f[1][1])
        if a[0] in ("ptr", "sp") or b[0] in ("ptr", "sp"):
            raise _NotMixer("a comparison of pointers")
        if a[0] == "c" and b[0] == "c":
            return _c(int((a[2] == b[2]) != negate), 1)
        return ("ne" if negate else "eq", 1, a, b)

    def fork(self):
        twin = _MixInterp(self.word, self.lo, self.hi, resolver=self.resolver)
        twin.regs, twin.stack = dict(self.regs), dict(self.stack)
        twin.flags, twin.cons = self.flags, list(self.cons)
        return twin

    def assume(self, cond) -> bool:
        """Add a path condition; False when it is constant-false (the path is infeasible)."""
        if cond[0] == "c":
            return bool(cond[2])
        self.cons.append(cond)
        return True

    def run(self, insns, x86, max_insns: int = MAX_MIXER_INSNS, max_paths: int = MAX_MIXER_PATHS):
        """Every path through the region: ``[(return node, interp)]``.  Forward in-region branches
        fork (each side carries its condition); a backward branch (a loop) raises."""
        at = {ins.address: k for k, ins in enumerate(insns)}
        done: list = []
        work = [(0, self)]
        steps = 0
        while work:
            k, st = work.pop()
            while True:
                if k >= len(insns):
                    raise _NotMixer("fell off the end of the region without a ret")
                steps += 1
                if steps > max_insns:
                    raise _NotMixer(f"over {max_insns} instructions")
                ins = insns[k]
                act = st.step(ins, x86)
                if act is None:
                    k += 1
                    continue
                if act[0] == "ret":
                    done.append((act[1], st))
                    break
                tgt = act[1]
                if tgt <= ins.address or tgt not in at:
                    raise _NotMixer("a backward or mid-instruction branch (a loop)")
                if act[0] == "goto":
                    k = at[tgt]
                    continue
                taken = st.fork()
                if taken.assume(act[2]):
                    work.append((at[tgt], taken))
                if len(done) + len(work) >= max_paths:
                    raise _NotMixer(f"over {max_paths} paths")
                if not st.assume(act[3]):
                    break
                k += 1
        return done

    # -- one instruction: None (fall through), ("ret", node), ("goto", addr), ("fork", addr, if-taken,
    #    if-not-taken)
    def step(self, ins, x86):
        wb = self.word // 8
        acc = "rax" if self.word == 64 else "eax"
        mn = ins.mnemonic
        ops = ins.operands
        if mn in ("nop", "endbr64", "endbr32"):
            return None
        if mn in ("ret", "retq"):
            return ("ret", self.reg_get(acc))
        if mn in ("mov", "movabs"):
            self.write(ins, ops[0], x86, self.read(ins, ops[1], x86, ops[0].size))
        elif mn == "movzx":
            self.write(ins, ops[0], x86, _fit(self.read(ins, ops[1], x86), ops[0].size * 8))
        elif mn in ("xor", "or", "and", "add", "sub"):
            if (mn in ("xor", "sub") and ops[0].type == x86.X86_OP_REG
                    and ops[1].type == x86.X86_OP_REG and ops[0].reg == ops[1].reg):
                r = _c(0, ops[0].size * 8)                 # the zero idiom
            else:
                a = self.read(ins, ops[0], x86)
                b = self.read(ins, ops[1], x86, ops[0].size)
                if a[0] in ("ptr", "sp") and mn in ("add", "sub") and b[0] == "c":
                    k = ops[1].imm if ops[1].type == x86.X86_OP_IMM else _signed(b[2], b[1])
                    r = (a[0], a[1], a[2] + (k if mn == "add" else -k))
                else:
                    r = _bin(mn, ops[0].size * 8, a, b)
            self.write(ins, ops[0], x86, r)
            self.flags = ("res", r) if r[0] not in ("ptr", "sp") else None
        elif mn in ("inc", "dec"):
            a = self.read(ins, ops[0], x86)
            r = _bin("add" if mn == "inc" else "sub", ops[0].size * 8, a, _c(1, ops[0].size * 8))
            self.write(ins, ops[0], x86, r)
            self.flags = ("res", r)
        elif mn == "not":
            a = self.read(ins, ops[0], x86)
            self.write(ins, ops[0], x86, _bin("xor", ops[0].size * 8, a,
                                              _c(-1, ops[0].size * 8)))
        elif mn == "neg":
            a = self.read(ins, ops[0], x86)
            r = _bin("mul", ops[0].size * 8, a, _c(-1, ops[0].size * 8))
            self.write(ins, ops[0], x86, r)
            self.flags = ("res", r)
        elif mn == "imul":
            if len(ops) == 2:
                r = _bin("mul", ops[0].size * 8, self.read(ins, ops[0], x86),
                         self.read(ins, ops[1], x86, ops[0].size))
            elif len(ops) == 3:
                r = _bin("mul", ops[0].size * 8, self.read(ins, ops[1], x86, ops[0].size),
                         self.read(ins, ops[2], x86, ops[0].size))
            else:
                raise _NotMixer("one-operand imul (a widening multiply)")
            self.write(ins, ops[0], x86, r)
            self.flags = None                          # ZF is undefined after imul
        elif mn in ("shr", "shl", "sal", "rol", "ror"):
            if len(ops) == 1:
                s = 1
            elif ops[1].type == x86.X86_OP_IMM:
                s = ops[1].imm
            else:
                cnt = self.read(ins, ops[1], x86)
                if cnt[0] != "c":
                    raise _NotMixer("a shift by a symbolic count")
                s = cnt[2]
            w = ops[0].size * 8
            r = _shift({"sal": "shl"}.get(mn, mn), w, self.read(ins, ops[0], x86), s)
            self.write(ins, ops[0], x86, r)
            if mn in ("shr", "shl", "sal"):
                self.flags = ("res", r) if s & (63 if w == 64 else 31) else self.flags
        elif mn == "lea":
            where = self.addr(ins, ops[1], x86)
            if where[0] == "sp":
                raise _NotMixer("address of a stack slot")
            self.reg_set(ins.reg_name(ops[0].reg), where)
        elif mn in ("cmp", "test"):
            a = self.read(ins, ops[0], x86)
            b = self.read(ins, ops[1], x86, ops[0].size)
            if mn == "cmp":
                self.flags = ("cmp", a, b)
            elif a == b:
                self.flags = ("res", a)
            else:
                self.flags = ("res", _bin("and", ops[0].size * 8, a, b))
        elif mn in ("sete", "setz", "setne", "setnz"):
            cond = self.zf_cond(negate=mn in ("setne", "setnz"))
            self.write(ins, ops[0], x86, cond if cond[0] == "c" else ("bool", 8, cond))
        elif mn in ("je", "jz", "jne", "jnz", "jmp"):
            if ops[0].type != x86.X86_OP_IMM:
                raise _NotMixer("an indirect jump")
            tgt = ops[0].imm
            inside = self.lo <= tgt < self.hi
            if mn == "jmp":
                if not inside:
                    raise _NotMixer("a jump out of the region (tail call)")
                return ("goto", tgt)
            if_eq = self.zf_cond(negate=False)
            if_ne = self.zf_cond(negate=True)
            taken, fall = (if_eq, if_ne) if mn in ("je", "jz") else (if_ne, if_eq)
            if inside:
                return ("fork", tgt, taken, fall)
            # leaving the region is the fail path: the accepted path does NOT take it
            if not self.assume(fall):
                raise _NotMixer("the accepted path is unreachable")
        elif mn == "push":
            if ops[0].type == x86.X86_OP_REG:
                canon = symbolic._REGMAP.get(ins.reg_name(ops[0].reg), (None,))[0]
                v = self.regs.get(canon)       # a callee-saved register may be opaque: kept as-is
            else:
                v = self.read(ins, ops[0], x86, wb)
            sp = self.regs["rsp"]
            self.regs["rsp"] = ("sp", self.word, sp[2] - wb)
            self.stack[sp[2] - wb] = (wb, v)
        elif mn == "pop":
            sp = self.regs["rsp"]
            if sp[2] not in self.stack:
                raise _NotMixer("pop of an unwritten stack slot")
            slot = self.stack[sp[2]]
            self.regs["rsp"] = ("sp", self.word, sp[2] + wb)
            if ops[0].type != x86.X86_OP_REG:
                raise _NotMixer("pop into memory")
            ent = symbolic._REGMAP.get(ins.reg_name(ops[0].reg))
            if ent is None or ent[1] != wb:
                raise _NotMixer("pop into a partial register")
            self.regs[ent[0]] = slot[1]        # None stays None: still unreadable
        elif mn == "call":
            self.call(ins, ops, x86)
        else:
            raise _NotMixer(f"instruction {mn} is not modelled")
        return None

    def call(self, ins, ops, x86):
        if ops[0].type != x86.X86_OP_IMM or self.resolver is None:
            raise _NotMixer("a call")
        found = self.resolver(ops[0].imm)
        if found is None:
            raise _NotMixer(f"a call to {ops[0].imm:#x}, which is not a recognised mixer function")
        mops, mw = found
        if self.word == 64:
            arg = _fit(self.reg_get("rdi"), mw)
        else:
            slot = self.stack.get(self.regs["rsp"][2])
            if slot is None or slot[0] != 4:
                raise _NotMixer("a cdecl call with no stacked argument")
            arg = _fit(slot[1], mw)
        res = _apply_ops_nodes(arg, mops, mw)
        for r in self._CALLER_SAVED if self.word == 64 else ("rax", "rcx", "rdx"):
            self.regs[r] = None
        self.reg_set("rax" if self.word == 64 else "eax", res if mw == self.word else _fit(res, 32))
        self.flags = None


def _disasm(code: bytes, arch: str, bits: int, base: int):
    try:
        import capstone
        from capstone import x86
    except Exception as exc:  # noqa: BLE001 - ImportError, or a None entry in sys.modules
        raise RuntimeError("invert_checks needs capstone in the venv; not importable") from exc
    cs_arch, mode, word = symbolic._cs_for(arch, bits)
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    return list(md.disasm(bytes(code), int(base))), x86, word


def recognise_mixer_function(code, *, arch: str = "amd64", bits: int = 64, base: int = 0,
                             resolver=None):
    """``(ops, width)`` when ``code`` is a function ``f(x) -> mixer(x)`` (the word argument in
    ``rdi``/``edi``, or the first stacked argument on i386; the result in ``rax``/``eax``) built only
    from invertible ops, with at least one multiply or xorshift; else None.  Reads code, never runs it."""
    insns, x86, word = _disasm(code, arch, bits, base)
    if not insns:
        return None
    it = _MixInterp(word, base, base + len(code), resolver=resolver)
    if word == 64:
        it.regs["rdi"] = ("arg", 64)
    else:
        it.stack[4] = (4, ("arg", 32))
    try:
        paths = it.run(insns, x86)
        if len(paths) != 1 or paths[0][1].cons:
            return None                           # a function with branches/checks is not a pure mixer
        ret = paths[0][0]
        for w in ((64, 32) if word == 64 else (32,)):
            got = _match_word(_fit(ret, w)) if ret[0] != "c" else None
            if got is None:
                continue
            b, mops = got
            # (a 32-bit match can only come from a zero-extended 32-bit result: _fit of any other
            # 64-bit tree to 32 bits is a "lo" node, which _match_word does not read through)
            if b[1] != w or not any(n in ("mul", "xorshift_right", "xorshift_left") for n, _ in mops):
                continue
            return mops, w
    except _NotMixer:
        return None
    return None


def _require(it, ret, success: str):
    """Add the accepted-path constraints of returning ``ret`` under ``success`` (nonzero/zero)."""
    def strip(v):
        while v[0] in ("zx", "lo") and v[2][0] in ("bool", "zx", "lo", "and", "c"):
            v = v[2]
        return v

    def nonzero(v):
        v = strip(v)
        if v[0] == "bool":
            it.cons.append(v[2])
        elif v[0] == "and" and all(strip(x)[0] in ("bool", "and") for x in (v[2], v[3])):
            nonzero(v[2])
            nonzero(v[3])
        elif v[0] == "c":
            if v[2] == 0:
                raise _Rejected("the path returns 0")
        else:
            raise _NotMixer("the return value is not a boolean of comparisons")

    def zero(v):
        while v[0] == "zx":                       # x == 0 exactly when its zero-extension is
            v = v[2]
        if v[0] == "or":
            zero(v[2])
            zero(v[3])
        elif v[0] == "c":
            if v[2] != 0:
                raise _Rejected("the path returns nonzero")
        elif v[0] == "bool":
            c = v[2]
            it.cons.append(("ne" if c[0] == "eq" else "eq", 1, c[2], c[3]))
        elif v[0] in ("ptr", "sp"):
            raise _NotMixer("returns a pointer")
        else:
            it.cons.append(("eq", 1, v, _c(0, v[1])))

    (nonzero if success == "nonzero" else zero)(ret)


@dataclass
class MixerSolution:
    """A mixer check inverted from code: the unique accepted input and the per-word ops recovered."""
    value: bytes
    words: list            # [(byte offset, width, ops, target)]
    success_return: str

    def describe(self) -> str:
        parts = []
        for off, w, mops, tgt in self.words:
            shown = ", ".join(f"{n} {k:#x}" if n in ("mul", "xor", "add", "sub") else f"{n} {k}"
                              for n, k in mops)
            parts.append(f"bytes {off}..{off + w // 8 - 1}: [{shown}] == {tgt:#x}")
        return "; ".join(parts)


def invert_mixer_check(code, *, arch: str = "amd64", bits: int = 64, base: int = 0,
                       success_return=("nonzero", "zero"), resolver=None):
    """Invert a straight-line WORD-MIXER check from its code, no signature, never wrong.

    The input pointer is ``rdi`` (amd64) / the first stacked argument (i386).  Returns a
    :class:`MixerSolution` whose ``value`` is the unique accepted input, or None (with nothing claimed)
    when the code is not exactly such a check, a word is not pinned by a bijective mixer equation, or
    the recovered input fails the independent re-check of every lifted constraint.  ``resolver(addr)``
    may return ``(ops, width)`` for a called mixer function (see :func:`recognise_mixer_function`)."""
    insns, x86, word = _disasm(code, arch, bits, base)
    if not insns:
        return None
    srs = [success_return] if isinstance(success_return, str) else list(success_return)
    for sr in srs:
        it = _MixInterp(word, base, base + len(code), resolver=resolver)
        if word == 64:
            it.regs["rdi"] = ("ptr", 64, 0)
        else:
            it.stack[4] = (4, ("ptr", 32, 0))
        try:
            accepted = []
            for ret, st in it.run(insns, x86):
                try:
                    _require(st, ret, sr)
                except _Rejected:
                    continue                      # this path returns a constant rejection
                accepted.append(st)
            if len(accepted) != 1:
                continue                          # no accepted path, or several (an OR): not pinned
            got = _pin_and_check(accepted[0].cons)
        except (_NotMixer, InvertError):
            continue
        if got is not None:
            value, words = got
            return MixerSolution(value=value, words=words, success_return=sr)
    return None


def _zero_atoms(c, out: list):
    """Split ``x == 0`` where ``x`` is an OR (or a zero-extension of one) into ``part == 0`` atoms:
    an OR is zero exactly when every part is.  Other constraints pass through unchanged."""
    if c[0] == "eq":
        a, b = c[2], c[3]
        if a[0] == "c":
            a, b = b, a
        if b[0] == "c" and b[2] == 0:
            while a[0] == "zx":
                a = a[2]
            if a[0] == "or":
                _zero_atoms(("eq", 1, a[2], _c(0, a[2][1])), out)
                _zero_atoms(("eq", 1, a[3], _c(0, a[3][1])), out)
                return
            out.append(("eq", 1, a, _c(0, a[1])))
            return
    out.append(c)


def _pin_and_check(cons):
    """Pin input words from ``term == 0`` / ``a == b`` constraints, assemble the input, then re-check
    every constraint on it.  None when some read byte is not pinned (not unique) or a check fails."""
    pinned: dict[int, int] = {}                     # byte offset -> value
    words = []
    atoms: list = []
    for c in cons:
        _zero_atoms(c, atoms)
    for c in atoms:
        if c[0] != "eq":
            continue
        a, b = c[2], c[3]
        if a[0] == "c":
            a, b = b, a
        if b[0] == "c":
            term, target = a, b[2]
            while term[0] == "zx":                  # zx(x) == t: x == t if t fits x, else never
                if target >> term[2][1]:
                    return None
                term = term[2]
        else:
            term, target = _bin("xor", a[1], a, b), 0
        got = _match_word(term)
        if got is None or got[0][0] != "ld":
            continue
        bnode, mops = got
        w, off = bnode[1], bnode[2]
        while mops and mops[-1][0] == "xor":        # `mix(x) ^ T == t`  is  `mix(x) == t ^ T`
            target ^= mops[-1][1] & _wmask(w)
            mops = mops[:-1]
        word_val = invert_mixer(target, mops, width=w) if mops else target
        for i, byte in enumerate(word_val.to_bytes(w // 8, "little")):
            if pinned.setdefault(off + i, byte) != byte:
                return None                         # two equations disagree: no accepted input
        words.append((off, w, mops, target))
    if not words:
        return None
    reads: set = set()
    seen: set = set()
    for c in cons:
        _loads(c, reads, seen)
    n = max(off + nb for off, nb in reads)
    if any(i not in pinned for i in range(n)):
        return None                                 # an input byte the check reads is not pinned
    value = bytes(pinned[i] for i in range(n))
    memo: dict = {}
    if not all(_eval(c, value, None, memo) for c in cons):
        return None
    return value, sorted(words, key=lambda t: t[0])


def _in_charset(value: bytes, charset) -> bool:
    if isinstance(charset, tuple) and len(charset) == 2 and all(isinstance(v, int) for v in charset):
        return all(charset[0] <= b <= charset[1] for b in value)
    allowed = {ord(c) for c in charset} if isinstance(charset, str) else {int(c) for c in charset}
    return all(b in allowed for b in value)


def _mixer_row(region, *, arch, bits, base, name, resolver=None, success_return=("nonzero", "zero")):
    """The word-mixer pass on one function region, as a :class:`Recovered` row (or None)."""
    try:
        sol = invert_mixer_check(region, arch=arch, bits=bits, base=base, resolver=resolver,
                                 success_return=success_return)
    except (_NotMixer, InvertError, ValueError):
        return None
    if sol is None:
        return None
    return Recovered(func=name, addr=base, length=len(sol.value), value=sol.value,
                     detail=(f"word-mixer check inverted algebraically and re-checked on the lifted "
                             f"code (return {sol.success_return}): {sol.describe()}"))


# ============================================================ automated straight-line ELF pass

@dataclass
class Recovered:
    """One accepted input recovered from an ELF check function."""
    func: str
    addr: int
    length: int
    value: bytes
    detail: str = ""
    caveat: str = ""          # an assumption the uniqueness proof rests on (e.g. a charset)

    def as_text(self) -> str:
        if self.value and all(0x20 <= c < 0x7F for c in self.value):
            return self.value.decode("latin-1")
        return self.value.hex()


class ElfSkipped(InvertError):
    """A whole file was not analysed, with the named reason (unsupported arch, too large, ...)."""


_PWN_TOOLKIT: list = []


def _pwn_toolkit():
    """The in-tree ``solvers/toolkits/pwn.py``, loaded BY PATH.

    A flat ``import pwn`` resolves by module name, so after an agent's ``from pwn import *``
    (pwntools, pinned in requirements.in) it would bind pwntools, which has no ``read_elf``.  Loading
    the file by path is immune to that; a missing file or a module without ``read_elf`` raises a named
    RuntimeError instead of degrading to an empty result."""
    if _PWN_TOOLKIT:
        return _PWN_TOOLKIT[0]
    import importlib.util
    path = TOOLKITS / "pwn.py"
    try:
        spec = importlib.util.spec_from_file_location("invert_checks_pwn_toolkit", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"invert_checks needs the ELF reader {path.name} in the toolkits lane; "
                           f"it did not load: {type(exc).__name__}: {exc}") from exc
    if not callable(getattr(mod, "read_elf", None)):
        raise RuntimeError(f"invert_checks: {path.name} has no read_elf()")
    _PWN_TOOLKIT.append(mod)
    return mod


def _read_elf(data: bytes):
    """The toolkit's read_elf of ``data``, or None for bytes that are not a parseable ELF.

    A missing/broken toolkit raises (see :func:`_pwn_toolkit`); only the CONTENT may make this None."""
    reader = _pwn_toolkit().read_elf
    try:
        return reader(bytes(data))
    except Exception:  # noqa: BLE001 - a malformed ELF is data, never a crash; caller names the skip
        return None


_STATIC_DEPS = (("capstone", "capstone"), ("elftools", "pyelftools"))


def _require_static_deps():
    """Raise a named RuntimeError when the disassembler (capstone) or the section reader (pyelftools)
    is not importable.  Without them the lift degrades to PARTIAL and read_elf to header facts only,
    which would otherwise read as "nothing to invert" -- a silent 'none'."""
    import importlib
    missing = []
    for mod, pkg in _STATIC_DEPS:
        try:
            importlib.import_module(mod)
        except Exception:  # noqa: BLE001 - ImportError, or a None entry in sys.modules
            missing.append(pkg)
    if missing:
        raise RuntimeError(f"invert_checks needs {' and '.join(missing)} in the venv "
                           f"(pinned in requirements.in); not importable")


def _exec_sections_full(blob: bytes):
    """Every executable PROGBITS section IN FULL, as ``[(name, addr, code)]``.

    ``pwn.read_elf`` truncates each section to its gadget-scan window (``GADGET_SCAN``), so a function
    further into ``.text`` would have no code; the file itself is already capped at MAX_ELF_BYTES."""
    import io
    from elftools.elf.elffile import ELFFile
    out = []
    elf = ELFFile(io.BytesIO(blob))
    for sec in elf.iter_sections():
        if sec["sh_flags"] & 0x4 and sec["sh_type"] == "SHT_PROGBITS" and sec.data_size:
            out.append((sec.name or "", sec["sh_addr"], sec.data()))
    return out


def _func_extents(info):
    """{func_addr: byte length} -- each function runs to the next function start in its section."""
    secs = info.get("exec_sections", []) if info else []
    funcs = sorted({a for _n, a in (info.get("functions", []) if info else [])})
    nxt = {a: b for a, b in zip(funcs, funcs[1:])}
    out = {}
    for addr in funcs:
        for _name, sec_addr, code in secs:
            if sec_addr <= addr < sec_addr + len(code):
                end = min(nxt.get(addr, sec_addr + len(code)), sec_addr + len(code))
                out[addr] = max(0, end - addr)
                break
    return out


def find_check_candidates(info, *, max_funcs: int = MAX_ELF_FUNCS):
    """Rank an ELF's functions by how much they look like a byte-compare check: a function whose code
    carries comparison/arith immediates (``cmp``/``test``/``xor``/...).  Returns ``[(name, addr)]``
    best first.  The ranking reads structure, never a specific constant.  ``main``/``check``-named
    functions and the entry point are always included.
    """
    if not info or info.get("arch") not in ("i386", "amd64"):
        return []
    bits = info.get("class") or (64 if info["arch"] == "amd64" else 32)
    secs = info.get("exec_sections", [])
    funcs = list(info.get("functions", []))
    # a function's code slice runs to the next function start inside the same section (capped).
    starts = sorted({a for _n, a in funcs})
    nxt = {a: b for a, b in zip(starts, starts[1:])}

    def slice_for(addr):
        for _name, sec_addr, code in secs:
            if sec_addr <= addr < sec_addr + len(code):
                end = min(nxt.get(addr, addr + 4096), sec_addr + len(code), addr + 4096)
                return code[addr - sec_addr:end - sec_addr]
        return b""

    scored = []
    for name, addr in funcs:
        blob = slice_for(addr)
        if not blob:
            continue
        imms = symbolic.scan_immediates(blob, arch=info["arch"], bits=bits, base=addr)
        cmps = sum(1 for _a, mn, _o, _i in imms if mn in ("cmp", "test"))
        logic = sum(1 for _a, mn, _o, _i in imms if mn in ("xor", "sub", "add", "rol", "ror"))
        named = any(k in name.lower() for k in ("check", "verify", "valid", "compare", "main"))
        score = cmps * 2 + logic + (100 if named else 0)
        if score:
            scored.append((score, addr, name))
    scored.sort(key=lambda t: (-t[0], t[1]))
    out = [(name, addr) for _s, addr, name in scored[:max_funcs]]
    # always try the entry point too (constructor-style checks live off _start)
    entry = info.get("entry")
    if isinstance(entry, int) and all(a != entry for _n, a in out):
        out.append(("entry", entry))
    return out


class ElfRows(list):
    """The ``[Recovered]`` rows of one ELF, plus ``budget_exhausted`` (the deadline stopped the sweep
    before every function/length/convention was tried) and ``skipped`` (candidate functions that were
    not analysed, each with its reason)."""

    def __init__(self, *args):
        super().__init__(*args)
        self.budget_exhausted = False
        self.skipped: list[str] = []
        self.mixers: list[tuple] = []      # (name, addr, width, ops) of recognised mixer functions
        self.notes: list[str] = []         # informational bounds that were hit (not incompleteness)


def _code_region(info, addr: int, max_bytes: int) -> bytes:
    for _name, sec_addr, code in info.get("exec_sections", []):
        if sec_addr <= addr < sec_addr + len(code):
            return code[addr - sec_addr:addr - sec_addr + max_bytes]
    return b""


def _lengths(lengths):
    if lengths is None:
        return list(DEFAULT_LENGTHS)
    out = []
    for n in lengths:
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_LEN:
            raise InvertError(f"input length {n!r} is not an int in 1..{MAX_LEN}")
        out.append(n)
    if not 1 <= len(out) <= MAX_ELF_LENGTHS:
        raise InvertError(f"give 1..{MAX_ELF_LENGTHS} input lengths (got {len(out)})")
    return out


def invert_elf_straightline(data, *, lengths=None, funcs=None, charset=None,
                            success_return=("nonzero", "zero"), max_bytes: int = 4096,
                            timeout_ms: int = DEFAULT_TIMEOUT_MS,
                            max_funcs: int = MAX_ELF_FUNCS, deadline=None):
    """Automated no-model pass: lift STRAIGHT-LINE x86/x86-64 check functions of an ELF and recover the
    accepted input with a z3 uniqueness proof.  Returns :class:`ElfRows` (a list of ``Recovered``, one
    per function+length that proved UNIQUE), best candidates first; empty when nothing proved unique.
    Nothing is executed -- ``symbolic.lift_linear`` reads the code and models it symbolically, degrading
    to a non-unique Solution (never a wrong answer) the moment a function is not straight-line.

    Raises :class:`ElfSkipped` naming why a file was NOT analysed at all (unreadable, larger than
    :data:`MAX_ELF_BYTES`, not a parseable ELF, an architecture other than i386/amd64), and
    :class:`InvertError` for a bad ``lengths`` or a ``funcs`` name the ELF does not define -- never a
    silent empty result for those.

    ``lengths``         input lengths to try (default :data:`DEFAULT_LENGTHS`); ``funcs`` restricts to
    named functions / integer addresses, else the candidates from :func:`find_check_candidates`.
    ``success_return``  the accepted-path model(s) to try: a single value (``"nonzero"``/``"zero"``/an
    int/None) or an iterable of them.  The default tries both the ``return 1`` and the branchless
    ``return 0`` conventions, since a crackme uses either.
    ``deadline``        a ``time.monotonic()`` value; once passed, the sweep stops and the result's
    ``budget_exhausted`` is True.
    """
    import time
    _require_static_deps()
    if isinstance(success_return, (str, int)) or success_return is None:
        srs = [success_return]
    else:
        srs = list(success_return)
    lengths = _lengths(lengths)
    if isinstance(data, (bytes, bytearray)):
        blob = bytes(data)
        if len(blob) > MAX_ELF_BYTES:
            raise ElfSkipped(f"larger than {MAX_ELF_BYTES} bytes ({len(blob)}), not lifted")
    else:
        try:
            size = Path(data).stat().st_size       # size BEFORE reading: never slurp an oversized file
        except (OSError, TypeError, ValueError) as exc:
            raise ElfSkipped(f"unreadable ({type(exc).__name__})") from exc
        if size > MAX_ELF_BYTES:
            raise ElfSkipped(f"larger than {MAX_ELF_BYTES} bytes ({size}), not lifted")
        try:
            blob = Path(data).read_bytes()
        except OSError as exc:
            raise ElfSkipped(f"unreadable ({type(exc).__name__})") from exc
    info = _read_elf(blob)
    if info is None:
        raise ElfSkipped("not a parseable ELF")
    if info.get("arch") not in ("i386", "amd64"):
        raise ElfSkipped(f"architecture {info.get('arch')!r} is not lifted (i386/amd64 only)")
    if not info.get("pyelftools"):
        raise ElfSkipped("its section and symbol tables could not be read (pyelftools parse failed)")
    try:
        full = _exec_sections_full(blob)
    except Exception as exc:  # noqa: BLE001 - a malformed section table is data; name the skip
        raise ElfSkipped(f"its executable sections could not be read ({type(exc).__name__})") from exc
    info = dict(info)
    info["exec_sections"] = full            # untruncated: read_elf keeps only a gadget-scan window
    arch = info["arch"]
    bits = info.get("class") or (64 if arch == "amd64" else 32)
    if funcs is not None:
        targets = []
        by_name = {n: a for n, a in info.get("functions", [])}
        missing = []
        for f in funcs:
            if isinstance(f, int) and not isinstance(f, bool):
                targets.append((hex(f), f))
            elif f in by_name:
                targets.append((f, by_name[f]))
            else:
                missing.append(f)
        if missing:
            raise InvertError(f"function(s) not defined in the ELF: {missing!r}")
    else:
        targets = find_check_candidates(info, max_funcs=max_funcs)
    # A function's extent runs to the next function start in the same section: slicing each function to
    # its own extent means a `jne` to a SEPARATE fail-handler function leaves the lifted region (and so
    # is modelled as "the check must pass"), instead of looking like an in-region jump (PARTIAL).
    extent = _func_extents(info)
    out = ElfRows()
    seen: set[tuple[int, bytes]] = set()
    explicit = funcs is not None
    fn_name = {a: n for n, a in info.get("functions", [])}
    mixer_cache: dict = {}
    mixer_srs = [s for s in srs if s in ("nonzero", "zero")]

    def resolver(target: int):
        """(ops, width) of a called function that is a pure invertible mixer, else None (memoised)."""
        if target not in mixer_cache:
            mixer_cache[target] = None
            if target in fn_name:
                reg = _code_region(info, target, min(max_bytes, extent.get(target, max_bytes)))
                if reg:
                    mixer_cache[target] = recognise_mixer_function(reg, arch=arch, bits=bits,
                                                                   base=target)
                    if mixer_cache[target] is not None:
                        out.mixers.append((fn_name[target], target) + mixer_cache[target][::-1])
        return mixer_cache[target]

    for name, addr in targets:
        mb = min(max_bytes, extent.get(addr, max_bytes))
        region = _code_region(info, addr, mb)
        if not region:
            why = f"{name} at {addr:#x} is not inside an executable section, not lifted"
            if explicit:
                raise InvertError(why)
            out.skipped.append(why)
            continue
        if deadline is not None and time.monotonic() >= deadline:
            out.budget_exhausted = True
            return out
        # The word-mixer pass first: a fixed-width xorshift/multiply chain compared to constants is
        # recognised from the code's structure and inverted algebraically (no length sweep needed).
        mrec = _mixer_row(region, arch=arch, bits=bits, base=addr, name=name, resolver=resolver,
                          success_return=mixer_srs) if mixer_srs else None
        if (mrec is not None and (addr, mrec.value) not in seen
                and (charset is None or _in_charset(mrec.value, charset))):
            seen.add((addr, mrec.value))
            out.append(mrec)
        resolver(addr)                     # a candidate that is itself a mixer function is reported
        for n in lengths:
            for sr in srs:
                if deadline is not None and time.monotonic() >= deadline:
                    out.budget_exhausted = True
                    return out
                sol = symbolic.lift_linear(region, n, arch=arch, bits=bits, base=addr,
                                           charset=charset, success_return=sr,
                                           timeout_ms=timeout_ms)
                if sol is not None and sol.status == symbolic.PARTIAL and sol.reason == "no-capstone":
                    raise RuntimeError("invert_checks needs capstone in the venv; not importable")
                if sol is None or not sol.is_unique:
                    continue
                val = sol.plain()
                if not isinstance(val, (bytes, bytearray)):
                    continue
                val = bytes(val)
                key = (addr, val)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Recovered(
                    func=name, addr=addr, length=n, value=val,
                    detail=f"z3 proved a unique {n}-byte input accepted by {name} (return {sr})"))
    if not explicit:
        # Report every small function that is itself an invertible mixer (a lead for the agent even
        # when the check that calls it is looped or reads a target table, which this pass refuses).
        for k, (_n, faddr) in enumerate(sorted(info.get("functions", []), key=lambda t: t[1])):
            if k >= MAX_MIXER_SCAN:
                out.notes.append(f"mixer-function scan covered the first {MAX_MIXER_SCAN} functions")
                break
            if deadline is not None and time.monotonic() >= deadline:
                out.budget_exhausted = True
                return out
            if extent.get(faddr, max_bytes + 1) <= MAX_MIXER_FUNC_BYTES:
                resolver(faddr)
    return out


# ============================================================ JVM per-position check pass
#
# The Trypophobia shape: a Java class whose boolean check(String) runs each character through a block
# of int arithmetic (with stack shuffles) and compares it to a constant.  The class file is read
# statically (never loaded or run), each method is decoded with bytecode_lifters.lift_jvm_code, and a
# small path-exploring emulator models the JVM int stack exactly (32-bit wrap) with the input
# characters as z3 16-bit symbols.  The accepted path's constraints then go to invert_positions (one
# z3 uniqueness proof per character) when every constraint touches one position, else to one joint
# z3 solve -- either way a key is reported only when z3 proved it the only accepted input.

MAX_JVM_STEPS = 200_000               # emulated instructions per method (all paths together)
MAX_JVM_PATHS = 4096                  # paths through the method's branches
MAX_JVM_ARRAY = 4096                  # elements in one method-local array
MAX_CLASS_BYTES = 16 * 1024 * 1024    # a class file larger than this is not read

_JVM_EXTRA = {
    0x2E: "iaload", 0x33: "baload", 0x34: "caload", 0x35: "saload",
    0x4B: "astore_0", 0x4C: "astore_1", 0x4D: "astore_2", 0x4E: "astore_3",
    0x4F: "iastore", 0x54: "bastore", 0x55: "castore", 0x56: "sastore",
    0x58: "pop2", 0x5A: "dup_x1", 0x5B: "dup_x2", 0x5C: "dup2", 0x5F: "swap",
    0x78: "ishl", 0x7A: "ishr", 0x7C: "iushr", 0x91: "i2b", 0x92: "i2c", 0x93: "i2s",
}
_JVM_IF = {"ifeq": "==", "ifne": "!=", "iflt": "<", "ifge": ">=", "ifgt": ">", "ifle": "<="}
_JVM_IFCMP = {"if_icmpeq": "==", "if_icmpne": "!=", "if_icmplt": "<", "if_icmpge": ">=",
              "if_icmpgt": ">", "if_icmple": "<="}
_ACC_STATIC = 0x0008


class _NotJvmCheck(Exception):
    """The method is not (exactly) a modelled per-character check; the reason names what was met."""


_LIFTERS: list = []


def _bytecode_lifters():
    """``solvers/binary/bytecode_lifters.py`` loaded by path (stdlib only), or a named RuntimeError."""
    if _LIFTERS:
        return _LIFTERS[0]
    import importlib.util
    path = HERE / "bytecode_lifters.py"
    name = "invert_checks_bytecode_lifters"      # private name: never shadows / is shadowed by an import
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod                  # dataclasses resolve annotations via sys.modules
        spec.loader.exec_module(mod)
    except Exception as exc:  # noqa: BLE001
        sys.modules.pop(name, None)
        raise RuntimeError(f"invert_checks needs the JVM decoder {path.name}; it did not load: "
                           f"{type(exc).__name__}: {exc}") from exc
    if not callable(getattr(mod, "lift_jvm_code", None)):
        raise RuntimeError(f"invert_checks: {path.name} has no lift_jvm_code()")
    _LIFTERS.append(mod)
    return mod


def is_class_file(head: bytes) -> bool:
    """CAFEBABE with a plausible class-file major version (45..80).  A Mach-O universal binary shares
    the magic, but its next word is a small architecture count, which reads as a major version < 45."""
    return len(head) >= 8 and head[:4] == b"\xca\xfe\xba\xbe" and 45 <= int.from_bytes(head[6:8], "big") <= 80


def _mutf8(raw: bytes) -> str:
    try:
        return raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass").encode(
            "utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        return raw.decode("utf-8", "replace")


def parse_jvm_class(blob: bytes) -> dict:
    """The constant pool and the methods (name, descriptor, access flags, Code bytes) of a class file,
    read from the bytes only.  ``facts.parse_class`` keeps only the Code bodies, not which method each
    belongs to nor the Methodref entries, and both are needed to pick a check(String) method and to
    resolve its ``charAt``/``length`` calls.  Raises :class:`InvertError` on a malformed class."""
    import struct
    try:
        if not is_class_file(blob[:8]):
            raise InvertError("not a Java class file")
        count = struct.unpack_from(">H", blob, 8)[0]
        pool: dict = {}
        i, at = 1, 10
        while i < count:
            tag = blob[at]
            if tag == 1:
                n = struct.unpack_from(">H", blob, at + 1)[0]
                if at + 3 + n > len(blob):
                    raise InvertError("a constant runs past the end of the class")
                pool[i] = ("utf8", _mutf8(blob[at + 3:at + 3 + n]))
                at += 3 + n
            elif tag == 3:
                pool[i] = ("int", struct.unpack_from(">i", blob, at + 1)[0])
                at += 5
            elif tag == 4:
                pool[i] = ("float",)
                at += 5
            elif tag in (5, 6):
                pool[i] = ("wide",)
                at += 9
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                pool[i] = ({7: "class", 8: "string"}.get(tag, "other"),
                           struct.unpack_from(">H", blob, at + 1)[0])
                at += 3
            elif tag in (9, 10, 11, 12, 17, 18):
                a, b = struct.unpack_from(">HH", blob, at + 1)
                pool[i] = ({9: "field", 10: "method", 11: "imethod", 12: "nat"}.get(tag, "other"), a, b)
                at += 5
            elif tag == 15:
                pool[i] = ("other",)
                at += 4
            else:
                raise InvertError(f"constant pool tag {tag} at {at}")
            i += 1
        _access, this_i = struct.unpack_from(">HH", blob, at)
        at += 6
        at += 2 + 2 * struct.unpack_from(">H", blob, at)[0]
        methods = []
        for member in ("fields", "methods"):
            n = struct.unpack_from(">H", blob, at)[0]
            at += 2
            for _ in range(n):
                acc, name_i, desc_i, attrs = struct.unpack_from(">HHHH", blob, at)
                at += 8
                code = None
                for _ in range(attrs):
                    a_name, a_len = struct.unpack_from(">HI", blob, at)
                    if member == "methods" and pool.get(a_name, ("",))[-1] == "Code":
                        clen = struct.unpack_from(">I", blob, at + 10)[0]
                        if at + 14 + clen > len(blob):
                            raise InvertError("a Code attribute runs past the end of the class")
                        code = blob[at + 14:at + 14 + clen]
                    at += 6 + a_len
                if member == "methods":
                    methods.append({"name": _utf(pool, name_i), "desc": _utf(pool, desc_i),
                                    "access": acc, "code": code})
        if at > len(blob):
            raise InvertError("the class is cut")
    except (struct.error, IndexError) as exc:
        raise InvertError(f"malformed class file ({type(exc).__name__})") from exc
    cls = pool.get(this_i)
    return {"pool": pool, "this": _utf(pool, cls[1]) if cls and cls[0] == "class" else None,
            "methods": methods}


def _utf(pool, idx):
    ent = pool.get(idx)
    if not ent or ent[0] != "utf8":
        raise InvertError(f"constant #{idx} is not a Utf8 entry")
    return ent[1]


def _methodref(pool, idx):
    ent = pool.get(idx)
    if not ent or ent[0] not in ("method", "imethod"):
        raise _NotJvmCheck(f"constant #{idx} is not a method reference")
    cls = pool.get(ent[1])
    nat = pool.get(ent[2])
    if not cls or cls[0] != "class" or not nat or nat[0] != "nat":
        raise _NotJvmCheck(f"method reference #{idx} is malformed")
    return _utf(pool, cls[1]), _utf(pool, nat[1]), _utf(pool, nat[2])


def _param_slots(desc: str, static: bool):
    """[(local slot, type descriptor)] of a method's parameters, and the return descriptor."""
    if not desc.startswith("(") or ")" not in desc:
        raise _NotJvmCheck(f"bad descriptor {desc!r}")
    body, ret = desc[1:].split(")", 1)
    out, slot, k = [], (0 if static else 1), 0
    while k < len(body):
        start = k
        while body[k] == "[":
            k += 1
        if body[k] == "L":
            k = body.index(";", k) + 1
        else:
            k += 1
        t = body[start:k]
        out.append((slot, t))
        slot += 2 if t in ("J", "D") else 1
    return out, ret


class _JvmState:
    def __init__(self):
        self.k = 0                     # instruction index
        self.stack: list = []
        self.locals: dict = {}
        self.arrays: dict = {}         # id -> list of BitVec(32)
        self.cons: list = []           # z3 BoolRefs on this path
        self.min_len = 0               # charAt(k) passed: len > k

    def fork(self):
        t = _JvmState()
        t.k, t.stack, t.locals = self.k, list(self.stack), dict(self.locals)
        t.arrays = {a: list(v) for a, v in self.arrays.items()}
        t.cons, t.min_len = list(self.cons), self.min_len
        return t


class _JvmEmu:
    """Path-exploring emulator of one JVM method: ints are z3 BitVec(32) (Java's wrap), the input
    String's characters are z3 BitVec(16) symbols ``in<k>`` and its length the BitVec(32) ``len``.
    Anything not modelled exactly raises _NotJvmCheck naming it (never a guess)."""

    def __init__(self, z3, pool):
        self.z3 = z3
        self.pool = pool
        self.chars: dict = {}
        self.len = z3.BitVec("len", 32)

    def char(self, k: int):
        if not 0 <= k < MAX_LEN:
            raise _NotJvmCheck(f"charAt({k}) is outside 0..{MAX_LEN - 1}")
        if k not in self.chars:
            self.chars[k] = self.z3.BitVec(f"in{k}", 16)
        return self.z3.ZeroExt(16, self.chars[k])

    def const(self, v):
        v = self.z3.simplify(v)
        if not self.z3.is_bv_value(v):
            raise _NotJvmCheck("a value that must be concrete (an index or array size) is symbolic")
        return _signed(v.as_long(), 32)

    def run(self, insns, input_slot: int, input_type: str):
        z3 = self.z3
        at = {ins.offset: k for k, ins in enumerate(insns)}
        st = _JvmState()
        st.locals[input_slot] = ("in",) if input_type == "Ljava/lang/String;" else ("chars",)
        work = [st]
        done = []
        steps = 0
        while work:
            st = work.pop()
            while True:
                steps += 1
                if steps > MAX_JVM_STEPS:
                    raise _NotJvmCheck(f"over {MAX_JVM_STEPS} emulated instructions")
                if not 0 <= st.k < len(insns):
                    raise _NotJvmCheck("ran off the end of the method")
                ins = insns[st.k]
                act = self.step(st, ins)
                if act is None:
                    st.k += 1
                    continue
                if act[0] == "return":
                    done.append((act[1], st))
                    break
                if act[0] == "die":
                    break
                if act[0] == "goto":
                    if act[1] not in at:
                        raise _NotJvmCheck("a branch into the middle of an instruction")
                    st.k = at[act[1]]
                    continue
                _, tgt, cond = act                   # "if": cond -> tgt, else fall through
                cond = z3.simplify(cond)
                if tgt not in at:
                    raise _NotJvmCheck("a branch into the middle of an instruction")
                if z3.is_true(cond):
                    st.k = at[tgt]
                    continue
                if z3.is_false(cond):
                    st.k += 1
                    continue
                taken = st.fork()
                taken.cons.append(cond)
                taken.k = at[tgt]
                work.append(taken)
                if len(done) + len(work) > MAX_JVM_PATHS:
                    raise _NotJvmCheck(f"over {MAX_JVM_PATHS} paths")
                st.cons.append(z3.Not(cond))
                st.k += 1
        return done

    def pop_int(self, st):
        if not st.stack:
            raise _NotJvmCheck("stack underflow")
        v = st.stack.pop()
        if isinstance(v, tuple):
            raise _NotJvmCheck("a reference where an int was expected")
        return v

    def pop_ref(self, st):
        if not st.stack:
            raise _NotJvmCheck("stack underflow")
        v = st.stack.pop()
        if not isinstance(v, tuple):
            raise _NotJvmCheck("an int where a reference was expected")
        return v

    def step(self, st, ins):
        z3 = self.z3
        mn = ins.mnemonic
        if mn.startswith("op_"):
            mn = _JVM_EXTRA.get(int(mn[3:], 16), mn)
        ops = ins.operands
        push = st.stack.append
        if mn == "nop":
            return None
        if mn.startswith("iconst_"):
            push(z3.BitVecVal(-1 if mn == "iconst_m1" else int(mn[7:]), 32))
        elif mn in ("bipush", "sipush"):
            push(z3.BitVecVal(int(ops[0]), 32))
        elif mn in ("ldc", "ldc_w"):
            idx = int(ops[0][3:] if ops[0].startswith("cp#") else ops[0])
            ent = self.pool.get(idx)
            if ent and ent[0] == "int":
                push(z3.BitVecVal(ent[1], 32))
            elif ent and ent[0] == "string":
                push(("str",))
            else:
                raise _NotJvmCheck(f"ldc of an unmodelled constant #{idx}")
        elif mn in ("iload", "aload") or mn[:6] in ("iload_", "aload_"):
            slot = int(ops[0]) if mn in ("iload", "aload") else int(mn[-1])
            if slot not in st.locals:
                raise _NotJvmCheck(f"read of local {slot}, which holds no modelled value")
            v = st.locals[slot]
            if (mn[0] == "i") == isinstance(v, tuple):
                raise _NotJvmCheck(f"local {slot} has the wrong kind for {mn}")
            push(v)
        elif mn in ("istore", "astore") or mn[:7] in ("istore_", "astore_"):
            slot = int(ops[0]) if mn in ("istore", "astore") else int(mn[-1])
            st.locals[slot] = self.pop_int(st) if mn[0] == "i" else self.pop_ref(st)
        elif mn == "iinc":
            slot, inc = int(ops[0]), int(ops[1])
            if slot not in st.locals or isinstance(st.locals[slot], tuple):
                raise _NotJvmCheck(f"iinc of local {slot}, which holds no int")
            st.locals[slot] = st.locals[slot] + inc
        elif mn in ("iadd", "isub", "imul", "iand", "ior", "ixor", "ishl", "ishr", "iushr",
                    "idiv", "irem"):
            b = self.pop_int(st)
            a = self.pop_int(st)
            if mn in ("ishl", "ishr", "iushr"):
                s = b & 31
                r = a << s if mn == "ishl" else (a >> s if mn == "ishr" else z3.LShR(a, s))
            elif mn in ("idiv", "irem"):
                d = self.const(b)
                if d == 0:
                    return ("die",)                  # ArithmeticException: not an accepted path
                r = (a / d) if mn == "idiv" else z3.SRem(a, d)
            else:
                r = {"iadd": lambda: a + b, "isub": lambda: a - b, "imul": lambda: a * b,
                     "iand": lambda: a & b, "ior": lambda: a | b, "ixor": lambda: a ^ b}[mn]()
            push(r)
        elif mn == "ineg":
            push(-self.pop_int(st))
        elif mn == "i2c":
            push(z3.ZeroExt(16, z3.Extract(15, 0, self.pop_int(st))))
        elif mn == "i2b":
            push(z3.SignExt(24, z3.Extract(7, 0, self.pop_int(st))))
        elif mn == "i2s":
            push(z3.SignExt(16, z3.Extract(15, 0, self.pop_int(st))))
        elif mn in ("pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "swap"):
            need = {"pop": 1, "pop2": 2, "dup": 1, "dup_x1": 2, "dup_x2": 3, "dup2": 2, "swap": 2}[mn]
            if len(st.stack) < need:
                raise _NotJvmCheck("stack underflow")
            s = st.stack                              # every modelled value is category 1
            if mn == "pop":
                s.pop()
            elif mn == "pop2":
                del s[-2:]
            elif mn == "dup":
                s.append(s[-1])
            elif mn == "dup_x1":
                s.insert(-2, s[-1])
            elif mn == "dup_x2":
                s.insert(-3, s[-1])
            elif mn == "dup2":
                s.extend(s[-2:])
            else:
                s[-1], s[-2] = s[-2], s[-1]
        elif mn in _JVM_IF:
            v = self.pop_int(st)
            return ("if", ins.branch_targets[0], _cmp(v, z3.BitVecVal(0, 32), _JVM_IF[mn]))
        elif mn in _JVM_IFCMP:
            b = self.pop_int(st)
            a = self.pop_int(st)
            return ("if", ins.branch_targets[0], _cmp(a, b, _JVM_IFCMP[mn]))
        elif mn in ("goto", "goto_w"):
            return ("goto", ins.branch_targets[0])
        elif mn == "ireturn":
            return ("return", self.pop_int(st))
        elif mn == "athrow":
            return ("die",)
        elif mn == "newarray":
            if ops[0] not in ("5", "8", "9", "10"):           # char, byte, short, int
                raise _NotJvmCheck(f"newarray of type {ops[0]}")
            n = self.const(self.pop_int(st))
            if not 0 <= n <= MAX_JVM_ARRAY:
                raise _NotJvmCheck(f"array of {n} elements")
            aid = len(st.arrays)
            st.arrays[aid] = [z3.BitVecVal(0, 32)] * n
            push(("arr", aid, int(ops[0])))
        elif mn in ("iastore", "castore", "bastore", "sastore"):
            v = self.pop_int(st)
            i = self.const(self.pop_int(st))
            ref = self.pop_ref(st)
            if ref[0] != "arr":
                raise _NotJvmCheck("a store into an array this method did not create")
            arr = st.arrays[ref[1]]
            if not 0 <= i < len(arr):
                return ("die",)
            if mn == "castore":
                v = z3.ZeroExt(16, z3.Extract(15, 0, v))
            elif mn == "bastore":
                v = z3.SignExt(24, z3.Extract(7, 0, v))
            elif mn == "sastore":
                v = z3.SignExt(16, z3.Extract(15, 0, v))
            arr[i] = v
        elif mn in ("iaload", "caload", "baload", "saload"):
            i = self.const(self.pop_int(st))
            ref = self.pop_ref(st)
            if ref[0] == "chars" and mn == "caload":
                if i < 0:
                    return ("die",)
                st.min_len = max(st.min_len, i + 1)
                push(self.char(i))
            elif ref[0] == "arr":
                arr = st.arrays[ref[1]]
                if not 0 <= i < len(arr):
                    return ("die",)
                push(arr[i])
            else:
                raise _NotJvmCheck(f"{mn} from an unmodelled array")
        elif mn == "arraylength":
            ref = self.pop_ref(st)
            if ref[0] == "chars":
                push(self.len)
            elif ref[0] == "arr":
                push(z3.BitVecVal(len(st.arrays[ref[1]]), 32))
            else:
                raise _NotJvmCheck("arraylength of an unmodelled array")
        elif mn in ("invokevirtual", "invokeinterface"):
            cls, name, desc = _methodref(self.pool, int(ops[0][3:]))
            if cls != "java/lang/String":
                raise _NotJvmCheck(f"a call to {cls}.{name}")
            if name == "charAt" and desc == "(I)C":
                i = self.const(self.pop_int(st))
                if self.pop_ref(st) != ("in",):
                    raise _NotJvmCheck("charAt on a string other than the input")
                if i < 0:
                    return ("die",)
                st.min_len = max(st.min_len, i + 1)
                push(self.char(i))
            elif name == "length" and desc == "()I":
                if self.pop_ref(st) != ("in",):
                    raise _NotJvmCheck("length() of a string other than the input")
                push(self.len)
            elif name == "toCharArray" and desc == "()[C":
                if self.pop_ref(st) != ("in",):
                    raise _NotJvmCheck("toCharArray() of a string other than the input")
                push(("chars",))
            else:
                raise _NotJvmCheck(f"a call to String.{name}{desc}")
        else:
            raise _NotJvmCheck(f"JVM instruction {mn} is not modelled")
        return None


def _cmp(a, b, op):
    return {"==": lambda: a == b, "!=": lambda: a != b, "<": lambda: a < b, ">=": lambda: a >= b,
            ">": lambda: a > b, "<=": lambda: a <= b}[op]()


def _jvm_solve(z3, emu, paths, *, timeout_ms, charset=None):
    """The unique accepted input of a method from its explored paths, or (None, reason)."""
    accepted = []
    for ret, st in paths:
        r = z3.simplify(ret)
        if z3.is_bv_value(r):
            if r.as_long() == 0:
                continue                                  # a path that returns false
            accepted.append(st.cons + [emu.len > st.min_len - 1])
        else:
            accepted.append(st.cons + [r != 0, emu.len > st.min_len - 1])
    if not accepted:
        return None, "no path returns true"
    if not emu.chars:
        return None, "the accepted path reads no input character"
    n_max = max(emu.chars) + 1
    gaps = [k for k in range(n_max) if k not in emu.chars]
    if gaps:
        return None, f"position(s) {gaps[:8]} are never read, so the key is not unique"
    lenv = emu.len
    base = [lenv >= 0, lenv <= MAX_LEN]
    xs = [emu.chars[k] for k in range(n_max)]
    names = [f"in{k}" for k in range(n_max)]
    allc = [z3.Or([z3.And(c) for c in accepted]) if len(accepted) > 1 else z3.And(accepted[0])] + base
    cons = accepted[0] if len(accepted) == 1 else None
    if cons is not None and all("len" not in _uses(z3, c) or _uses(z3, c) == {"len"} for c in cons) \
            and all(len(_uses(z3, c)) <= 1 for c in cons):
        # every constraint pins one character (or only the length): solve position by position
        groups: dict = {}
        for c in cons:
            for nm in _uses(z3, c) - {"len"}:
                groups.setdefault(int(nm[2:]), []).append(c)
        sol = invert_positions(n_max, lambda i, x: groups.get(i, []), width=16, charset=charset,
                               timeout_ms=timeout_ms)
        how = f"invert_positions: each of the {n_max} positions z3-proved unique"
    else:
        # an OR of accepted paths, or constraints that tie positions together: one joint proof
        cs = symbolic.charset_constraints(xs, charset) if charset is not None else []
        sol = symbolic.solve(xs, allc + cs, timeout_ms=timeout_ms, var_names=names)
        how = "one joint z3 solve over every position, proved unique"
    if not sol.is_unique:
        return None, f"characters not unique: {sol.detail}"
    chars = [sol.models[0][nm] for nm in names]
    # the length, with the characters fixed: pinned (then it must equal the positions read), or free
    fixed = allc + [x == v for x, v in zip(xs, chars)]
    lsol = symbolic.solve([lenv], fixed, timeout_ms=timeout_ms, var_names=["len"])
    if lsol.status == symbolic.UNIQUE:
        if lsol.models[0]["len"] != n_max:
            return None, (f"the length is {lsol.models[0]['len']} but only {n_max} position(s) are "
                          f"checked, so the key is not unique")
        return (chars, how + "; length pinned"), None
    if lsol.status in (symbolic.MULTIPLE, symbolic.UNDERCONSTRAINED):
        exact = symbolic.solve([lenv], fixed + [lenv == n_max], timeout_ms=timeout_ms,
                               var_names=["len"])
        if exact.status == symbolic.UNIQUE:
            return (chars, how + "; the length is not checked: this is the shortest accepted key"), None
    return None, f"the length is {lsol.status} with the recovered characters"


def _uses(z3, expr) -> set:
    out, seen, todo = set(), set(), [expr]
    while todo:
        e = todo.pop()
        if e.get_id() in seen:
            continue
        seen.add(e.get_id())
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            out.add(e.decl().name())
        todo.extend(e.children())
    return out


def invert_jvm_class(blob, *, timeout_ms: int = DEFAULT_TIMEOUT_MS, methods=None, charset=None):
    """Recover the accepted input of each per-character check method in a Java class file.

    A method qualifies when it takes a ``String`` (or ``char[]``) and returns ``boolean`` (true = accepted);
    ``methods`` restricts to the named ones (an unknown name raises :class:`InvertError`).  Returns
    ``(rows, skipped)``: ``rows`` the :class:`Recovered` keys z3 proved unique (``func`` is
    ``Class.method``), ``skipped`` ``[(method, reason)]`` for each candidate method not inverted.
    ``charset`` (a ``(lo, hi)`` range or an iterable) restricts every character; by default each is
    solved over Java's full 16-bit ``char`` domain, so uniqueness is exact.
    Nothing is loaded or run: the bytes are decoded and emulated symbolically."""
    z3 = symbolic._require_z3()
    lifters = _bytecode_lifters()
    if not isinstance(blob, (bytes, bytearray)):
        raise InvertError("give the class file's bytes")
    if len(blob) > MAX_CLASS_BYTES:
        raise ElfSkipped(f"class file larger than {MAX_CLASS_BYTES} bytes, not read")
    cls = parse_jvm_class(bytes(blob))
    pool = cls["pool"]
    names = {m["name"] for m in cls["methods"]}
    if methods is not None:
        missing = [m for m in methods if m not in names]
        if missing:
            raise InvertError(f"method(s) not defined in the class: {missing!r}")
    rows, skipped = [], []
    for m in cls["methods"]:
        if methods is not None and m["name"] not in methods:
            continue
        label = f"{cls['this']}.{m['name']}"
        try:
            params, ret = _param_slots(m["desc"], bool(m["access"] & _ACC_STATIC))
        except _NotJvmCheck as exc:
            skipped.append((label, str(exc)))
            continue
        inputs = [(s, t) for s, t in params if t in ("Ljava/lang/String;", "[C")]
        if ret != "Z" or not inputs or m["code"] is None:
            if methods is not None:
                skipped.append((label, "not a boolean method taking a String or char[]"))
            continue
        try:
            insns = lifters.lift_jvm_code(m["code"]).instructions
            emu = _JvmEmu(z3, pool)
            paths = emu.run(insns, *inputs[0])
            got, why = _jvm_solve(z3, emu, paths, timeout_ms=timeout_ms, charset=charset)
        except _NotJvmCheck as exc:
            skipped.append((label, str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 - a malformed method body is data: name it
            skipped.append((label, f"{type(exc).__name__}: {exc}"))
            continue
        if got is None:
            skipped.append((label, why))
            continue
        chars, how = got
        if charset is not None:
            caveat = f"unique only among characters in {charset!r}"
            how += "; " + caveat
        else:
            caveat = ""
        text = "".join(chr(c) for c in chars)
        value = bytes(chars) if all(c < 0x100 for c in chars) else text.encode("utf-8")
        rows.append(Recovered(func=label, addr=0, length=len(chars), value=value,
                              detail=f"JVM per-character check emulated and inverted ({how})",
                              caveat=caveat))
    return rows, skipped


# ----------------------------------------------------------------------------- engine entry
_SKIP_DIRS = {"recon", "unpacked"}
_ELF_MAGIC = b"\x7fELF"


def _handout_files(challenge_dir: Path, limit: int = MAX_HANDOUT_FILES):
    """``([(path, "elf"|"class")], over)``: the ELF and Java class files under ``files/`` and the
    challenge root (intake's ``recon/``/``unpacked/`` output and symlinks skipped), at most ``limit``
    of them; ``over`` counts the further ones found, which are named in solve()'s notes, not tried."""
    import os
    roots = [challenge_dir / "files", challenge_dir]
    seen: set[Path] = set()
    out: list = []
    over = 0
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not (here / d).is_symlink())
            for nm in sorted(filenames):
                f = here / nm
                if f.is_symlink() or not f.is_file() or f.resolve() in seen:
                    continue
                try:
                    with open(f, "rb") as fh:
                        head = fh.read(8)
                except OSError:
                    continue
                kind = "elf" if head[:4] == _ELF_MAGIC else "class" if is_class_file(head) else None
                if kind is None:
                    continue
                seen.add(f.resolve())
                if len(out) < limit:
                    out.append((f, kind))
                else:
                    over += 1
    return out, over


def _decompile_dir(challenge_dir: Path):
    d = challenge_dir / "recon" / "decompile"
    return d if d.is_dir() else None


PRINTABLE = (0x20, 0x7E)


def _invert_class_file(path: Path):
    """The JVM pass on one handout class file: exact 16-bit characters first; a method whose
    characters are not unique there is retried over printable ASCII (said in the row's detail).
    Returns ``(rows, skipped)``; raises :class:`ElfSkipped` naming why a file was not read."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ElfSkipped(f"unreadable ({type(exc).__name__})") from exc
    if size > MAX_CLASS_BYTES:
        raise ElfSkipped(f"class file larger than {MAX_CLASS_BYTES} bytes ({size}), not read")
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise ElfSkipped(f"unreadable ({type(exc).__name__})") from exc
    try:
        rows, skipped = invert_jvm_class(blob)
    except ElfSkipped:
        raise
    except InvertError as exc:
        raise ElfSkipped(f"not a readable class file ({exc})") from exc
    retry = [m.rsplit(".", 1)[-1] for m, why in skipped if why.startswith("characters not unique")]
    if retry:
        more, _still = invert_jvm_class(blob, methods=retry, charset=PRINTABLE)
        done = {r.func for r in more}
        rows = rows + more
        skipped = [(m, w) for m, w in skipped if m not in done]
    return rows, skipped


DEFAULT_BUDGET_S = 45.0               # solve()'s whole-run wall-clock budget across every file
_ENGINE = "binary.invert_checks"


def _fmt_ops(ops) -> str:
    return ", ".join(f"{n} {k:#x}" if n in ("mul", "xor", "add", "sub") else f"{n} {k}"
                     for n, k in ops)


def solve(challenge_dir, profile, *, timeout_ms: int = DEFAULT_TIMEOUT_MS, lengths=None,
          budget_s=DEFAULT_BUDGET_S, **_opts):
    """Engine entry: invert the handout's checks with no model -- straight-line byte-compare and
    word-mixer checks in i386/amd64 ELFs, per-character checks in Java class files.

    ``candidate`` when a recovered accepted input is itself in the event flag format.  ``unsure`` when
    an input was recovered but is not a flag (the common case -- the flag is usually DERIVED from the
    key, which a model/agent finishes, so the recovered bytes go in the notes/evidence); when a mixer
    function was recognised but no check using it was inverted (its ops are in the notes); or when
    the sweep was incomplete: a file errored or was skipped while others were analysed, a candidate
    function could not be lifted, more handout files than ``MAX_HANDOUT_FILES`` were found, or the
    ``budget_s`` time budget ran out -- each reason named.  ``blocked`` when z3, capstone, pyelftools
    or an in-tree reader is missing, or no handout file could be analysed at all (each skip named).
    ``none`` only when every handout file was analysed to completion and nothing proved unique.
    Never executes a binary.
    """
    import time
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    if isinstance(lengths, str):                 # --opt lengths=4,8,14
        lengths = [int(x) for x in lengths.replace(",", " ").split()]
    budget_s = float(budget_s)
    if budget_s < 0:
        raise InvertError("budget_s must be >= 0 seconds")
    try:                                         # preflight: a missing dependency is BLOCKED, named
        symbolic._require_z3()
        _require_static_deps()
        _pwn_toolkit()
        _bytecode_lifters()
    except RuntimeError as exc:
        return SolverResult(status="blocked", engine=_ENGINE, notes=f"cannot run: {exc}")
    ff = flagfmt.for_profile(profile)
    files, over = _handout_files(challenge_dir)
    if not files:
        return SolverResult(status="none", engine=_ENGINE,
                            notes="no ELF binary or Java class file in the handout to invert")
    deadline = time.monotonic() + budget_s
    decomp = _decompile_dir(challenge_dir)
    recovered: list[Evidence] = []
    flags: list[str] = []
    recovered_notes: list[str] = []
    errors: list[str] = []          # a file whose analysis raised or stopped short: incomplete
    skips: list[str] = []           # a file that was not analysed, with the reason
    leads: list[str] = []           # recognised mixer functions, JVM methods not inverted
    mixer_ev: list[Evidence] = []
    analysed = 0
    out_of_time = False
    if over:
        skips.append(f"{over} more ELF/class file(s) beyond the cap of {MAX_HANDOUT_FILES} "
                     f"not tried")
    for f, kind in files:
        rel = str(f.relative_to(challenge_dir))
        if time.monotonic() >= deadline:
            out_of_time = True
            skips.append(f"{rel}: not tried, time budget of {budget_s:g} s used up")
            continue
        try:
            if kind == "elf":
                found = invert_elf_straightline(f, lengths=lengths, timeout_ms=timeout_ms,
                                                deadline=deadline)
            else:
                found, jskips = _invert_class_file(f)
                leads.extend(f"{rel}:{m} not inverted ({why})" for m, why in jskips)
        except ElfSkipped as exc:
            skips.append(f"{rel}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 - a malformed binary is data; report, never crash
            errors.append(f"{rel}: inversion error ({type(exc).__name__}: {exc})")
            continue
        analysed += 1
        if getattr(found, "budget_exhausted", False):
            out_of_time = True
            errors.append(f"{rel}: sweep stopped, time budget of {budget_s:g} s used up")
        errors.extend(f"{rel}: {why}" for why in getattr(found, "skipped", []))
        leads.extend(f"{rel}: {why}" for why in getattr(found, "notes", []))
        for name, addr, width, mops in getattr(found, "mixers", []):
            line = f"{rel}:{name} at {addr:#x} is a {width}-bit invertible mixer [{_fmt_ops(mops)}]"
            mixer_ev.append(Evidence(kind="mixer-function", detail=line, path=rel))
            leads.append(line + " (invert its compare targets with invert_mixer)")
        for r in found:
            recovered.append(Evidence(kind="recovered-input",
                                      detail=f"{rel}: {r.detail}: {r.as_text()!r}", path=rel))
            recovered_notes.append(f"{rel}:{r.func} accepts {r.as_text()!r}"
                                   + (f" ({r.caveat})" if r.caveat else ""))
            for fl in ff.find_flags(r.as_text()):
                if fl not in flags:
                    flags.append(fl)
    evidence = list(recovered) + mixer_ev
    if decomp is not None:
        evidence.append(Evidence(kind="decompile", detail="B-011 decompile output available",
                                 path=str(decomp.relative_to(challenge_dir))))
    problems = errors + skips
    tail = ("; incomplete: " + "; ".join(problems)) if problems else ""
    lead_tail = ("; leads: " + "; ".join(leads)) if leads else ""
    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence),
                            engine=_ENGINE,
                            notes="recovered input is in the flag format (proved unique, static). "
                                  + "; ".join(recovered_notes) + tail + lead_tail)
    if recovered:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=_ENGINE,
                            notes=("recovered accepted input(s), each proved unique (not a flag -- "
                                   "the flag is likely derived from the key): "
                                   + "; ".join(recovered_notes) + tail + lead_tail))
    if analysed == 0 and not errors and not out_of_time:
        return SolverResult(status="blocked", evidence=tuple(evidence), engine=_ENGINE,
                            notes=("no handout ELF or class file could be analysed: "
                                   + "; ".join(skips)))
    if problems:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=_ENGINE,
                            notes=("nothing recovered, but the sweep did not complete: "
                                   + "; ".join(problems) + lead_tail))
    if mixer_ev:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=_ENGINE,
                            notes="no check inverted, but mixer function(s) were recognised" + lead_tail)
    return SolverResult(status="none", engine=_ENGINE, evidence=tuple(evidence),
                        notes=("every handout file was analysed; no straight-line byte-compare, "
                               "word-mixer or JVM per-character check inverted to a unique input "
                               "(looped native checks need a loop-aware lifter; see the build log)"
                               + lead_tail))


if __name__ == "__main__":            # manual: python solvers/binary/invert_checks.py <elf> [len...]
    import json
    path = Path(sys.argv[1])
    lens = [int(x) for x in sys.argv[2:]] or None
    rows = invert_elf_straightline(path.read_bytes(), lengths=lens)
    print(json.dumps([{"func": r.func, "addr": hex(r.addr), "length": r.length,
                       "input": r.as_text()} for r in rows], indent=2))
