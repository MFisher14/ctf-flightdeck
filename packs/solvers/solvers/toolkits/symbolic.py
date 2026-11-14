#!/usr/bin/env python3
"""Toolkit symbolic: a z3-backed constraint / crackme solver that recovers a PROVEN input value
never-wrong. Built 2026-10-23 (gap analysis Section B, docs/retro/ctf-solver-gap-analysis.md:
"z3 bounded constraint-recovery primitive"). Composes with solvers/toolkits/pwn.py (ELF recon,
capstone) to READ comparison constants out of a disassembly; the solving itself is pure z3 over
constraints the agent extracted. z3 5.1.0 is in .venv.

What it does, all OFFLINE and executing NOTHING:
  - take a set of z3 constraints (lifted by the agent from a simple check function, a sequence of
    comparisons, an extracted equation system, or a stated byte transform) and solve with z3;
  - prove UNIQUENESS: find a model, then add the negation ("some variable differs") and confirm it
    is UNSAT. Only then is the model the one and only satisfying input, and only then is a value
    returned PLAIN. This uniqueness proof is what makes a symbolic answer never-wrong.

NEVER-WRONG rule (AGENTS.md "Uncertain answers", the gap analysis's never-wrong contract):
  - exactly one model (negation UNSAT, proved inside the time budget)  -> PLAIN value;
  - 2..MAX_CANDIDATES models, all enumerated                           -> UNSURE candidates, bounded
                                                                          <= 12, NEVER plain;
  - more than MAX_CANDIDATES models (underconstrained)                 -> None;
  - z3 timeout / unknown / incomplete (uniqueness not proved)          -> None;
  - contradictory constraints (UNSAT)                                  -> None.
  A value is PLAIN only on a z3-proved unique model; everything else is None or an unsure
  candidate list. The flag is NEVER what this tool proves (it proves the INPUT that satisfies the
  extracted constraints); a flag is the agent's / player's and is never derived or submitted here.

BOUNDED (the gap analysis: "bounded + time-boxed so a provably-unique solve can run on-clock"):
  - a HARD wall-clock budget across every z3 check (DEFAULT_TIMEOUT_MS, clamped to MAX_TIMEOUT_MS);
  - per-variable bit-width cap (MAX_BITS), variable-count cap (MAX_VARS), constraint-count cap
    (MAX_CONSTRAINTS), keygen length cap (MAX_BYTES), and at most MAX_CANDIDATES + 1 enumeration
    rounds. No binary is executed; no capstone-lifted code is run. Disassembly is READ only, to
    extract candidate comparison constants the agent then puts into constraints.

HAND TOOL (like web_exploit.py / java_deser.py / classical.py / pwn_target.py): there is NO
signals() and NO solve_set(); it is NOT in solvers/toolkits/registry.py, is never matched to a
lane, and is never on a timed path. The agent calls it from Python (or the CLI below) and submits
any finding BY HAND through tools/verify.py. tests/test_toolkit_registry.py lists it with the
other hand tools.

  .venv/bin/python solvers/toolkits/symbolic.py --selftest        # prove the engine on tiny cases
  .venv/bin/python solvers/toolkits/symbolic.py <elf>...          # READ cmp constants (recon only)

By hand, from Python (run with -I when any file of a delivery is on sys.path):

    import sys; sys.path.insert(0, "solvers/toolkits"); import symbolic as S
    import z3

    # A keygen-style check lifted to constraints over 4 input bytes:
    def build(x):                      # x is [BitVec8, BitVec8, ...]
        return [x[0] ^ 0xAA == 0xE1,   #  -> x0 = 0x4b
                x[1] ^ x[0] == 0x78,   #  -> x1 pinned once x0 is
                x[2] + x[1] == 0xAC,
                x[3] == 0x21]
    sol = S.keygen(4, build, charset=S.printable())   # Solution
    sol.status            # "UNIQUE"
    sol.plain()           # b'K3y!'   (ONLY when UNIQUE; None otherwise)
    sol.candidate_values()   # []     ([...] only when status == "MULTIPLE", never plain)

    # Raw z3 (an equation system / a stated transform):
    a, b = z3.Ints("a b")
    S.solve([a, b], [a + b == 7, a - b == 1])   # UNIQUE -> {"a": 4, "b": 3}
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"

# ---------------------------------------------------------------------------- bounds (hard caps)

DEFAULT_TIMEOUT_MS = 8000        # wall-clock budget for a whole solve, across every z3 check
MAX_TIMEOUT_MS = 30000           # a caller cannot ask for an unbounded solve
MAX_CANDIDATES = 12              # labels.MAX_OPTIONS: never plain with more than one model; a
                                 # candidate list past this means underconstrained -> None
MAX_VARS = 4096                  # variables in one problem
MAX_CONSTRAINTS = 200000         # constraints in one problem
MAX_BITS = 1024                  # bit-width of a single BitVec variable
MAX_BYTES = 4096                 # bytes a keygen may solve for

# Solution statuses.
UNIQUE = "UNIQUE"                # proved: exactly one model  -> plain
MULTIPLE = "MULTIPLE"            # 2..MAX_CANDIDATES models, all enumerated -> unsure candidates
UNDERCONSTRAINED = "UNDERCONSTRAINED"   # more than MAX_CANDIDATES models   -> None
UNSAT = "UNSAT"                  # contradictory constraints  -> None
TIMEOUT = "TIMEOUT"              # z3 timeout / unknown / incomplete; uniqueness not proved -> None
ERROR = "ERROR"                  # a z3 error during solving   -> None
PARTIAL = "PARTIAL"              # the lift did not faithfully model every instruction/operand -> None
PLAIN_STATUSES = frozenset({UNIQUE})

__all__ = ["Solution", "solve", "keygen", "solve_bitvecs", "solve_ints", "printable",
           "charset_constraints", "scan_immediates", "cmp_constants",
           "lift_linear", "lift_elf",
           "UNIQUE", "MULTIPLE", "UNDERCONSTRAINED", "UNSAT", "TIMEOUT", "ERROR", "PARTIAL",
           "DEFAULT_TIMEOUT_MS", "MAX_CANDIDATES", "MAX_INSNS"]


# ---------------------------------------------------------------------------- z3 helpers

def _require_z3():
    try:
        import z3  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("symbolic.py needs z3 (it is in .venv: .venv/bin/python)") from exc
    return z3


def _py(val):
    """A z3 model value as a plain Python value. BitVec values come back UNSIGNED, in [0, 2**n)."""
    z3 = _require_z3()
    try:
        if z3.is_bv_value(val):
            return val.as_long()
        if z3.is_int_value(val):
            return val.as_long()
        if z3.is_true(val):
            return True
        if z3.is_false(val):
            return False
        if z3.is_rational_value(val):
            return val.as_fraction()
    except Exception:  # noqa: BLE001 - an exotic sort falls through to its text
        pass
    return str(val)


_MAX_CONSTRAINT_DEPTH = 64       # nesting bound so a pathological structure is a clean ValueError


def _as_list(constraints, _depth=0):
    """A single BoolRef or an iterable of them, as a flat list. None/[] is no constraint."""
    z3 = _require_z3()
    if constraints is None:
        return []
    if z3.is_ast(constraints):
        return [constraints]
    if _depth > _MAX_CONSTRAINT_DEPTH:
        raise ValueError("constraints are nested beyond the supported depth")
    try:
        iterator = iter(constraints)
    except TypeError as exc:
        raise ValueError("constraints must be a z3 BoolRef or an iterable of them") from exc
    out = []
    for c in iterator:
        if isinstance(c, (list, tuple)):
            out.extend(_as_list(c, _depth + 1))
        else:
            out.append(c)
    return out


# ---------------------------------------------------------------------------- the result

class Solution:
    """What a solve proved. `status` is one of the module constants; only `UNIQUE` is PLAIN-eligible.

    plain()             the proved value when (and only when) status == UNIQUE, else None. A
                        byte-based solve (keygen with byte_bits == 8) decodes to `bytes`; a single
                        variable gives its value; several variables give a {name: value} dict.
    candidate_values()  the bounded, fully enumerated model values when status == MULTIPLE (never
                        plain, at most MAX_CANDIDATES); [] for every other status, so None/timeout/
                        underconstrained offer nothing.
    models              every enumerated model, each a {name: value} dict, best (first-found) first.
    """

    def __init__(self, status, models, var_names, *, byte_bits=None, timeout_ms=None,
                 elapsed=0.0, checks=0, detail="", reason=""):
        self.status = status
        self.models = list(models or [])
        self.var_names = list(var_names or [])
        self.byte_bits = byte_bits
        self.timeout_ms = timeout_ms
        self.elapsed = round(float(elapsed), 4)
        self.checks = checks
        self.detail = detail
        self.reason = reason            # z3's reason_unknown() on a timeout, for triage

    # ---- never-wrong readouts ----
    @property
    def is_unique(self) -> bool:
        return self.status == UNIQUE

    def _decode(self, model):
        """One model dict -> the value the caller wants: bytes for an 8-bit keygen, the lone
        variable's value for a one-variable solve, else the {name: value} dict itself."""
        if self.byte_bits == 8 and self.var_names:
            try:
                return bytes(int(model[n]) & 0xFF for n in self.var_names)
            except (KeyError, TypeError, ValueError):
                return dict(model)
        if len(self.var_names) == 1 and self.var_names[0] in model:
            return model[self.var_names[0]]
        return dict(model)

    def plain(self):
        """The PLAIN value: the one proved input, only when status == UNIQUE. None otherwise.

        This is the never-wrong boundary of the whole tool: a value crosses it only after z3 has
        proved (negation UNSAT, inside the budget) that no other input satisfies the constraints."""
        if self.status not in PLAIN_STATUSES or not self.models:
            return None
        return self._decode(self.models[0])

    def candidate_values(self) -> list:
        """The unsure candidate values (never plain), only when a small set of models was fully
        enumerated (status == MULTIPLE). [] for UNIQUE (use plain()), and for every status that
        proved nothing bounded (None/timeout/underconstrained/unsat/error)."""
        if self.status != MULTIPLE:
            return []
        return [self._decode(m) for m in self.models]

    def labels_candidates(self, key, render=None):
        """Optional convenience: the candidate_values() as a labels.candidates(key, options) unsure
        answer (backlog row 346), never plain. `key` must carry a lane / toolkit prefix labels.py
        knows (e.g. 'binary.key/crackme', 'pwn.input/crackme'); an unknown prefix -> None, like
        pwn.py. `render` maps a value to its submitted text (default: printable bytes as latin-1,
        else hex; anything else via str). Returns None unless status == MULTIPLE."""
        vals = self.candidate_values()
        if not vals:
            return None
        if str(COMMON) not in sys.path:
            sys.path.insert(1, str(COMMON))
        try:
            import labels  # noqa: E402
        except Exception:  # noqa: BLE001
            return None
        render = render or _default_render
        options = [(f"model{i + 1}", render(v)) for i, v in enumerate(vals)]
        try:
            return labels.candidates(key, options)
        except ValueError:          # labels.py does not know the key's prefix
            return None

    def __repr__(self):
        head = f"Solution({self.status}, models={len(self.models)}, vars={len(self.var_names)}"
        head += f", {self.elapsed}s, checks={self.checks}"
        if self.reason:
            head += f", reason={self.reason!r}"
        return head + ")"


def _default_render(value):
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if b and all(0x20 <= c < 0x7F for c in b):
            return b.decode("latin-1")
        return b.hex()
    return str(value)


# ---------------------------------------------------------------------------- the engine

def _validate(variables, constraints, timeout_ms, max_candidates):
    z3 = _require_z3()
    variables = list(variables or [])
    if not variables:
        raise ValueError("solve: pass at least one z3 variable to solve for")
    if len(variables) > MAX_VARS:
        raise ValueError(f"solve: {len(variables)} variables exceeds MAX_VARS ({MAX_VARS})")
    for v in variables:
        if not (z3.is_const(v) and v.decl().kind() == z3.Z3_OP_UNINTERPRETED):
            raise ValueError(f"solve: {v!r} is not a free z3 variable (declare with z3.BitVec/Int/Bool)")
        if z3.is_bv(v) and v.size() > MAX_BITS:
            raise ValueError(f"solve: {v} is {v.size()} bits, over MAX_BITS ({MAX_BITS})")
    cons = _as_list(constraints)
    if len(cons) > MAX_CONSTRAINTS:
        raise ValueError(f"solve: {len(cons)} constraints exceeds MAX_CONSTRAINTS ({MAX_CONSTRAINTS})")
    for c in cons:
        if not (z3.is_ast(c) and z3.is_bool(c)):
            raise ValueError(f"solve: {c!r} is not a boolean z3 constraint")
    try:
        timeout_ms = max(1, min(int(timeout_ms), MAX_TIMEOUT_MS))
        max_candidates = max(1, min(int(max_candidates), MAX_CANDIDATES))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timeout_ms and max_candidates must be integers") from exc
    return variables, cons, timeout_ms, max_candidates


def solve(variables, constraints, *, timeout_ms=DEFAULT_TIMEOUT_MS, max_candidates=MAX_CANDIDATES,
          byte_bits=None, var_names=None):
    """Solve `constraints` for `variables` with z3 and return a never-wrong Solution.

    variables       a list of free z3 consts (z3.BitVec/Int/Bool). Solved for simultaneously.
    constraints     a z3 BoolRef or an iterable of them (an equation system, a sequence of
                    comparisons, a lifted check). An empty set means "no constraint" (every
                    assignment is a model -> underconstrained).
    timeout_ms      the HARD wall-clock budget for the whole solve, across every z3 check, clamped
                    to [1, MAX_TIMEOUT_MS]. On expiry: TIMEOUT, uniqueness not proved, no plain.
    max_candidates  the most models to enumerate before declaring the problem underconstrained
                    (clamped to [1, MAX_CANDIDATES]).

    The method: enumerate distinct models under one shared deadline, blocking each as it is found.
      - the solver returns UNSAT with 0 models found     -> UNSAT (contradiction);
      - UNSAT after exactly 1 model (so no other exists) -> UNIQUE (plain-eligible);
      - UNSAT after 2..max_candidates models             -> MULTIPLE (unsure candidates);
      - a (max_candidates + 1)-th model is found         -> UNDERCONSTRAINED (None);
      - the deadline or an `unknown` cuts the search     -> TIMEOUT (None).
    UNSAT-after-one is a sound uniqueness proof: z3 proved no model differs from the one found."""
    z3 = _require_z3()
    variables, cons, timeout_ms, max_candidates = _validate(
        variables, constraints, timeout_ms, max_candidates)
    names = list(var_names) if var_names is not None else [str(v) for v in variables]
    if len(names) != len(variables):
        raise ValueError("solve: var_names must match variables one-for-one")

    started = time.monotonic()
    deadline = started + timeout_ms / 1000.0
    s = z3.Solver()
    for c in cons:
        s.add(c)

    models, checks = [], 0
    status, reason = None, ""
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status, reason = TIMEOUT, "deadline reached"
                break
            s.set("timeout", max(1, int(remaining * 1000)))
            checks += 1
            r = s.check()
            if r == z3.sat:
                m = s.model()
                vals = {n: _py(m.eval(v, model_completion=True)) for n, v in zip(names, variables)}
                models.append(vals)
                if len(models) > max_candidates:
                    status = UNDERCONSTRAINED      # more than the cap: not a usable candidate set
                    break
                block = [v != m.eval(v, model_completion=True) for v in variables]
                s.add(z3.Or(block))
            elif r == z3.unsat:
                # No (further) model. Every solution has been enumerated.
                if not models:
                    status = UNSAT
                elif len(models) == 1:
                    status = UNIQUE                # proved: nothing differs from the one model
                else:
                    status = MULTIPLE
                break
            else:  # z3.unknown
                status, reason = TIMEOUT, (s.reason_unknown() or "unknown")
                break
    except z3.Z3Exception as exc:
        status, reason = ERROR, str(exc)

    elapsed = time.monotonic() - started
    detail = _describe(status, len(models), max_candidates, timeout_ms, reason)
    kept = models if status in (UNIQUE, MULTIPLE) else []
    return Solution(status, kept, names, byte_bits=byte_bits, timeout_ms=timeout_ms,
                    elapsed=elapsed, checks=checks, detail=detail, reason=reason)


def _describe(status, n_models, cap, timeout_ms, reason) -> str:
    if status == UNIQUE:
        return "z3 proved a unique satisfying model (negation UNSAT); the value is plain"
    if status == MULTIPLE:
        return (f"{n_models} satisfying models, all enumerated; unsure candidates only (<= {cap}), "
                "never plain")
    if status == UNDERCONSTRAINED:
        return (f"more than {cap} satisfying models: underconstrained, no unique input; None "
                "(add constraints)")
    if status == UNSAT:
        return "constraints are contradictory (no model); None"
    if status == TIMEOUT:
        return (f"z3 did not finish within {timeout_ms} ms ({reason or 'timeout'}); uniqueness not "
                "proved; None")
    if status == ERROR:
        return f"z3 error: {reason}; None"
    if status == PARTIAL:
        return (f"the straight-line lift did not faithfully model the code ({reason or 'partial'}); "
                "uniqueness cannot be claimed; None")
    return status or ""


# ---------------------------------------------------------------------------- keygen / byte helpers

def printable():
    """The inclusive (lo, hi) byte range of printable ASCII, for `charset`."""
    return (0x20, 0x7E)


def charset_constraints(xs, charset):
    """z3 constraints restricting each BitVec in `xs` to `charset`.

    charset is an inclusive (lo, hi) range (unsigned), or an explicit iterable of allowed byte
    values (bytes/str/ints). Comparisons are UNSIGNED (z3.UGE/ULE), so a byte's top bit is not a
    sign."""
    z3 = _require_z3()
    xs = list(xs)

    def _top(x):
        # the inclusive maximum a variable can hold; charset values must fit it so that an
        # out-of-range byte is rejected rather than silently wrapped by z3's modular BitVec.
        return (1 << x.size()) - 1 if z3.is_bv(x) else None

    out = []
    if isinstance(charset, tuple) and len(charset) == 2 and all(isinstance(v, int) for v in charset):
        lo, hi = charset
        for x in xs:
            top = _top(x)
            if lo < 0 or lo > hi or (top is not None and hi > top):
                raise ValueError("charset range is outside the variable's value range")
            out.append(z3.And(z3.UGE(x, lo), z3.ULE(x, hi)))
        return out
    if isinstance(charset, str):
        allowed = sorted({ord(c) for c in charset})
    elif charset is None:
        raise ValueError("charset_constraints: charset must be a (lo, hi) range or an iterable of values")
    else:
        try:
            allowed = sorted({(c if isinstance(c, int) else int(c)) for c in charset})
        except TypeError as exc:
            raise ValueError("charset_constraints: charset must be a (lo, hi) range or an iterable of values") from exc
    if not allowed:
        raise ValueError("charset_constraints: empty charset")
    for x in xs:
        top = _top(x)
        for a in allowed:
            if a < 0 or (top is not None and a > top):
                raise ValueError("charset value is outside the variable's value range")
        out.append(z3.Or([x == a for a in allowed]))
    return out


def keygen(length, build, *, byte_bits=8, charset=None, name="b",
           timeout_ms=DEFAULT_TIMEOUT_MS, max_candidates=MAX_CANDIDATES):
    """Solve for `length` input bytes whose check `build` passes, never-wrong.

    build       a callable build(xs) -> constraints, where xs is the list of `length` z3 BitVecs
                (each `byte_bits` wide). It returns the lifted check as z3 constraints (a list, or
                one BoolRef). This is the "simple check function / sequence of comparisons / stated
                transform" entry: express the check over the symbolic bytes and z3 recovers the
                input. Nothing of the real binary is executed.
    charset     an optional range/iterable (see charset_constraints) every byte must fall in
                (e.g. printable()).
    Returns a Solution whose plain()/candidate_values() decode to `bytes` when byte_bits == 8."""
    _require_z3()
    import z3
    try:
        length = int(length)
    except (TypeError, ValueError) as exc:
        raise ValueError("keygen: length must be an integer") from exc
    if not 1 <= length <= MAX_BYTES:
        raise ValueError(f"keygen: length {length} out of range 1..{MAX_BYTES}")
    width = int(byte_bits)
    if not 1 <= width <= MAX_BITS:
        raise ValueError(f"keygen: byte_bits {width} out of range 1..{MAX_BITS}")
    xs = [z3.BitVec(f"{name}{i}", width) for i in range(length)]
    if not callable(build):
        raise TypeError("keygen: build must be a callable build(xs) -> constraints")
    cons = _as_list(build(xs))
    if charset is not None:
        cons = cons + charset_constraints(xs, charset)
    names = [f"{name}{i}" for i in range(length)]
    return solve(xs, cons, timeout_ms=timeout_ms, max_candidates=max_candidates,
                 byte_bits=(width if width == 8 else None), var_names=names)


def solve_bitvecs(widths, build, *, name="v", timeout_ms=DEFAULT_TIMEOUT_MS,
                  max_candidates=MAX_CANDIDATES):
    """Solve for several BitVec variables of the given `widths` (an int for all-equal, or a list of
    per-variable widths). `build(vs)` returns the constraints. Like keygen but for mixed/wider
    words (registers, a packed key)."""
    _require_z3()
    import z3
    if isinstance(widths, int):
        raise ValueError("solve_bitvecs: pass a list of widths (use keygen for N equal bytes)")
    try:
        ws = [int(w) for w in widths]
    except (TypeError, ValueError) as exc:
        raise ValueError("solve_bitvecs: widths must be an iterable of integers") from exc
    if not ws:
        raise ValueError("solve_bitvecs: no widths given")
    for w in ws:
        if not 1 <= w <= MAX_BITS:
            raise ValueError(f"solve_bitvecs: width {w} out of range 1..{MAX_BITS}")
    vs = [z3.BitVec(f"{name}{i}", w) for i, w in enumerate(ws)]
    if not callable(build):
        raise TypeError("solve_bitvecs: build must be callable")
    cons = _as_list(build(vs))
    names = [f"{name}{i}" for i in range(len(vs))]
    return solve(vs, cons, timeout_ms=timeout_ms, max_candidates=max_candidates, var_names=names)


def solve_ints(count, build, *, name="n", timeout_ms=DEFAULT_TIMEOUT_MS,
               max_candidates=MAX_CANDIDATES):
    """Solve for `count` unbounded integer variables of an equation system. `build(ns)` returns the
    constraints. Unique only if the system pins every variable; otherwise underconstrained -> None."""
    _require_z3()
    import z3
    try:
        count = int(count)
    except (TypeError, ValueError) as exc:
        raise ValueError("solve_ints: count must be an integer") from exc
    if not 1 <= count <= MAX_VARS:
        raise ValueError(f"solve_ints: count {count} out of range 1..{MAX_VARS}")
    ns = [z3.Int(f"{name}{i}") for i in range(count)]
    if not callable(build):
        raise TypeError("solve_ints: build must be callable")
    cons = _as_list(build(ns))
    names = [f"{name}{i}" for i in range(count)]
    return solve(ns, cons, timeout_ms=timeout_ms, max_candidates=max_candidates, var_names=names)


# ---------------------------------------------------------------------------- disassembly recon (READ ONLY)

# Instructions whose immediate operand is, in a check routine, usually a constant the input is
# compared / combined with. READ out as CANDIDATE constants for the agent to put into constraints;
# nothing here runs any instruction.
_IMM_MNEMONICS = ("cmp", "test", "xor", "sub", "add", "and", "or", "mov", "lea", "rol", "ror",
                  "shl", "shr", "sar", "mul", "imul")
MAX_SCAN = 256 * 1024            # bytes of code disassembled in one scan


def scan_immediates(code, arch="amd64", bits=64, base=0, max_scan=MAX_SCAN):
    """READ immediate constants out of raw machine code with capstone. Returns a list of
    (address, mnemonic, op_str, immediate) for comparison / arithmetic / move instructions that
    carry an immediate. x86 / x86-64 only (capstone, in .venv); [] when capstone is absent, the
    arch is unsupported, or `code` is empty. Nothing is executed; this is a static listing of
    constants to feed into z3 constraints. Bounded to `max_scan` bytes."""
    if not code:
        return []
    try:
        import capstone
        from capstone import x86
    except Exception:  # noqa: BLE001
        return []
    arch = str(arch).lower()
    if arch in ("amd64", "x86_64", "x86-64", "x64"):
        cs_arch, mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
    elif arch in ("i386", "x86", "x86-32", "ia32"):
        cs_arch, mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
    else:
        return []
    if bits == 32 and cs_arch == capstone.CS_ARCH_X86:
        mode = capstone.CS_MODE_32
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    out = []
    try:
        for ins in md.disasm(bytes(code[:max_scan]), base):
            mn = ins.mnemonic.split()[0] if ins.mnemonic else ""
            if mn not in _IMM_MNEMONICS:
                continue
            for op in ins.operands:
                if op.type == x86.X86_OP_IMM:
                    out.append((ins.address, mn, ins.op_str, int(op.imm)))
    except Exception:  # noqa: BLE001 - a bad byte stream costs its listing, never a crash
        return out
    return out


def cmp_constants(path_or_data, max_scan=MAX_SCAN):
    """READ candidate comparison constants out of an ELF's executable sections (via pwn.read_elf +
    capstone). Returns {"arch","bits","sections": [(name, [(addr, mnemonic, op_str, imm), ...])]}
    or None when the bytes are not an ELF / have no readable code. x86 / x86-64 only. Nothing is
    executed; the immediates are DATA for the agent to lift into z3 constraints."""
    if isinstance(path_or_data, (bytes, bytearray)):
        data = bytes(path_or_data)
    else:
        try:
            data = Path(path_or_data).read_bytes()
        except (OSError, TypeError, ValueError):
            return None
    if str(HERE) not in sys.path:
        sys.path.insert(1, str(HERE))
    try:
        import pwn as _pwn  # solvers/toolkits/pwn.py: ELF recon
    except Exception:  # noqa: BLE001
        return None
    info = _pwn.read_elf(data)
    if info is None or info["arch"] not in ("i386", "amd64"):
        return None
    bits = info["class"] or (64 if info["arch"] == "amd64" else 32)
    sections = []
    for sec_name, addr, blob in info.get("exec_sections", []):
        imms = scan_immediates(blob, arch=info["arch"], bits=bits, base=addr, max_scan=max_scan)
        if imms:
            sections.append((sec_name, imms))
    if not sections:
        return None
    return {"arch": info["arch"], "bits": bits, "sections": sections}


# ---------------------------------------------------------------------------- straight-line lift (capstone -> z3)
#
# Auto-lift a STRAIGHT-LINE x86/x86-64 check routine (reference build list row 7). capstone READS the
# instructions; this lifter translates a bounded, exactly-modelled subset into z3 expressions over the
# N symbolic input bytes, collects the path constraints that make the "pass" path hold, and solve()
# proves uniqueness. The value is PLAIN only on a z3-proved UNIQUE model (solve()'s blocking-clause
# proof); 2..MAX_CANDIDATES models are unsure candidates; more, or a timeout/contradiction, is None.
#
# NEVER-WRONG, and why PARTIAL exists: a value is trusted only when the lift is FAITHFUL. The moment the
# lifter meets anything it does not model exactly -- an unsupported instruction, a register read before it
# was defined, a memory access that is not the input buffer or a written stack slot, an index-register or
# segment address, a call, an in-window jump (a loop or forward skip, i.e. not straight-line), a flag whose
# producer leaves it undefined -- it raises _Partial and the result is Solution(PARTIAL): plain() is None
# and candidate_values() is []. So an incompletely-understood routine never yields a plain (or even a
# candidate) answer; it degrades to None. Nothing of the binary is ever executed.
#
# The success path (the caller's model of "accepted"): the lifter follows the fall-through of the region;
# every conditional branch whose target is OUTSIDE the region is a check that must NOT be taken to reach the
# end (the canonical `cmp ...; jne fail` crackme), so its negation is asserted; reaching `ret`/the region end
# asserts the return register meets `success_return` (default "nonzero": the routine returns true on a good
# key). An in-window branch is not straight-line -> _Partial. This is the caller's success model; z3's
# uniqueness is over exactly these asserted constraints.

MAX_INSNS = 4096                 # instructions lifted in one straight-line region (a hard bound)

_GPR64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def _build_regmap():
    """name -> (canonical 64-bit reg, size in bytes, is_high_byte)."""
    m = {}
    base = {"rax": ("al", "ax", "eax", "rax", "ah"),
            "rcx": ("cl", "cx", "ecx", "rcx", "ch"),
            "rdx": ("dl", "dx", "edx", "rdx", "dh"),
            "rbx": ("bl", "bx", "ebx", "rbx", "bh"),
            "rsp": ("spl", "sp", "esp", "rsp", None),
            "rbp": ("bpl", "bp", "ebp", "rbp", None),
            "rsi": ("sil", "si", "esi", "rsi", None),
            "rdi": ("dil", "di", "edi", "rdi", None)}
    for canon, (b, w, d, q, h) in base.items():
        m[b] = (canon, 1, False)
        m[w] = (canon, 2, False)
        m[d] = (canon, 4, False)
        m[q] = (canon, 8, False)
        if h:
            m[h] = (canon, 1, True)
    for i in range(8, 16):
        c = f"r{i}"
        m[f"{c}b"] = (c, 1, False)
        m[f"{c}w"] = (c, 2, False)
        m[f"{c}d"] = (c, 4, False)
        m[c] = (c, 8, False)
    return m


_REGMAP = _build_regmap()

# jcc mnemonic (without the leading 'j') -> the flags it needs, as a callable of the flag dict.
_SKIP_MNEMONICS = frozenset({"nop", "endbr64", "endbr32", "fnop", "pause"})


class _Partial(Exception):
    """The lift met something it does not model faithfully; the result must be None (never plain)."""


class _Lifter:
    """A bounded, exactly-modelled symbolic executor for one straight-line x86/x86-64 region.

    Registers hold z3 BitVec(64) values (32-bit writes zero-extend, as x86-64 does); a register is read
    only after it was defined (else _Partial). The input buffer is N symbolic bytes reached through a
    pointer-tainted register; the stack is modelled as written slots only (a read of an unwritten slot is
    _Partial). Memory writes go only to the stack; anything else is _Partial. Flags come from the exact
    producing op; a jcc needing an undefined flag is _Partial."""

    def __init__(self, z3, in_vars, word_bits, md, code_lo, code_hi, success_return):
        self.z3 = z3
        self.in_vars = in_vars
        self.n = len(in_vars)
        self.word = word_bits
        self.md = md
        self.code_lo = code_lo
        self.code_hi = code_hi
        self.success_return = success_return
        self.regv = {}            # canonical reg -> z3 BitVec(64) value (only when defined)
        self.regt = {}            # canonical reg -> ("input"|"stack", offset) or None
        self.stack = {}           # stack offset -> (size_bytes, expr, taint)
        self.flags = None         # (kind, a, b, res, size_bits)
        self.constraints = []

    # ---- widths ----
    def _fit(self, val, bits):
        z3 = self.z3
        vb = val.size()
        if vb == bits:
            return val
        if vb > bits:
            return z3.Extract(bits - 1, 0, val)
        return z3.ZeroExt(bits - vb, val)

    # ---- registers ----
    def _ensure(self, canon):
        """Define a register that is read before it was set with an opaque caller-state ('env') value.
        This is safe because the final soundness gate (only input bytes may appear in the constraints)
        turns any env value that reaches the success constraints into PARTIAL; env values that merely
        ride through a prologue's save/restore never do."""
        if canon not in self.regv:
            self.regv[canon] = self.z3.BitVec(f"env_{canon}", 64)
            self.regt[canon] = None
        return self.regv[canon]

    def reg_read(self, name):
        canon, size, high = _REGMAP[name]
        v = self._ensure(canon)
        if high:
            return self.z3.Extract(15, 8, v)
        return self.z3.Extract(size * 8 - 1, 0, v)

    def reg_write(self, name, val, taint):
        z3 = self.z3
        canon, size, high = _REGMAP[name]
        val = self._fit(val, size * 8)
        if size == 8:
            new = val
        elif size == 4:
            new = z3.ZeroExt(32, val)
        elif size == 2:
            cur = self._ensure(canon)
            new = z3.Concat(z3.Extract(63, 16, cur), val)
        elif size == 1 and not high:
            cur = self._ensure(canon)
            new = z3.Concat(z3.Extract(63, 8, cur), val)
        else:  # high byte
            cur = self._ensure(canon)
            new = z3.Concat(z3.Extract(63, 16, cur), val, z3.Extract(7, 0, cur))
        self.regv[canon] = new
        self.regt[canon] = taint if size >= 4 else None

    # ---- operands ----
    def op_rd(self, op, x86, want_bits=None):
        """Return (value, taint) for one capstone operand."""
        if op.type == x86.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name is None or name not in _REGMAP:
                raise _Partial(f"unsupported register operand {name}")
            canon = _REGMAP[name][0]
            return self.reg_read(name), self.regt.get(canon)
        if op.type == x86.X86_OP_IMM:
            bits = want_bits or (op.size * 8)
            return self.z3.BitVecVal(int(op.imm), bits), None
        if op.type == x86.X86_OP_MEM:
            return self.mem_rd(op, x86)
        raise _Partial("unsupported operand type")

    def _mem_target(self, op, x86):
        m = op.mem
        if m.segment != 0:
            raise _Partial("segment-relative memory access")
        if m.index != 0:
            raise _Partial("indexed memory access")
        if m.base == 0:
            raise _Partial("absolute memory access")
        bname = self.md.reg_name(m.base)
        if bname is None or bname not in _REGMAP:
            raise _Partial(f"unsupported base register {bname}")
        canon = _REGMAP[bname][0]
        taint = self.regt.get(canon)
        if taint is None:
            raise _Partial(f"memory through untainted register {bname}")
        kind, off = taint
        return kind, off + int(m.disp), op.size

    def mem_rd(self, op, x86):
        z3 = self.z3
        kind, addr, size = self._mem_target(op, x86)
        if kind == "input":
            if addr < 0 or addr + size > self.n:
                raise _Partial(f"input read out of the declared {self.n} bytes (off {addr}, size {size})")
            cells = [self.in_vars[addr + i] for i in range(size)]
            expr = cells[0] if size == 1 else z3.Concat(list(reversed(cells)))
            return expr, None
        # stack
        cell = self.stack.get(addr)
        if cell is None or cell[0] != size:
            raise _Partial(f"read of an unwritten/mismatched stack slot (off {addr}, size {size})")
        return cell[1], cell[2]

    def mem_wr(self, op, x86, val, taint):
        kind, addr, size = self._mem_target(op, x86)
        if kind != "stack":
            raise _Partial("memory write outside the modelled stack")
        self.stack[addr] = (size, self._fit(val, size * 8), taint)

    def write_op(self, op, x86, val, taint):
        if op.type == x86.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name is None or name not in _REGMAP:
                raise _Partial(f"unsupported register destination {name}")
            self.reg_write(name, val, taint)
        elif op.type == x86.X86_OP_MEM:
            self.mem_wr(op, x86, val, taint)
        else:
            raise _Partial("unsupported destination operand")

    # ---- flags ----
    def flag_exprs(self):
        if self.flags is None:
            raise _Partial("a conditional branch with no flags set")
        z3 = self.z3
        kind, a, b, res, size = self.flags
        msb = size - 1
        zf = res == 0
        sf = z3.Extract(msb, msb, res) == 1
        cf = of = None
        cf_ok = of_ok = False
        if kind in ("sub", "cmp"):
            cf = z3.ULT(a, b)
            of = z3.Extract(msb, msb, (a ^ b) & (a ^ res)) == 1
            cf_ok = of_ok = True
        elif kind == "add":
            cf = z3.ULT(res, a)
            of = z3.Extract(msb, msb, (~(a ^ b)) & (a ^ res)) == 1
            cf_ok = of_ok = True
        elif kind in ("and", "or", "xor", "test"):
            cf = z3.BoolVal(False)
            of = z3.BoolVal(False)
            cf_ok = of_ok = True
        elif kind == "inc":          # +1: CF preserved (undefined here), OF defined
            of = z3.Extract(msb, msb, (~(a ^ b)) & (a ^ res)) == 1
            of_ok = True
        elif kind == "dec":          # -1: CF preserved (undefined here), OF defined
            of = z3.Extract(msb, msb, (a ^ b) & (a ^ res)) == 1
            of_ok = True
        elif kind == "shift":        # only ZF/SF faithful for a constant shift
            pass
        else:                        # mul/undefined flag source
            return None
        return {"ZF": zf, "SF": sf, "CF": cf, "OF": of, "cf_ok": cf_ok, "of_ok": of_ok}

    def jcc_taken(self, base):
        """The z3 bool under which conditional branch `j<base>` is TAKEN."""
        z3 = self.z3
        fe = self.flag_exprs()
        if fe is None:
            raise _Partial("a conditional branch on undefined flags (mul/imul)")

        def need_cf():
            if not fe["cf_ok"]:
                raise _Partial("a branch on CF whose producer left it undefined")
            return fe["CF"]

        def need_of():
            if not fe["of_ok"]:
                raise _Partial("a branch on OF whose producer left it undefined")
            return fe["OF"]

        zf, sf = fe["ZF"], fe["SF"]
        if base in ("e", "z"):
            return zf
        if base in ("ne", "nz"):
            return z3.Not(zf)
        if base == "s":
            return sf
        if base == "ns":
            return z3.Not(sf)
        if base in ("b", "c", "nae"):
            return need_cf()
        if base in ("ae", "nb", "nc"):
            return z3.Not(need_cf())
        if base in ("be", "na"):
            return z3.Or(need_cf(), zf)
        if base in ("a", "nbe"):
            return z3.And(z3.Not(need_cf()), z3.Not(zf))
        if base in ("l", "nge"):
            return sf != need_of()
        if base in ("ge", "nl"):
            return sf == need_of()
        if base in ("le", "ng"):
            return z3.Or(zf, sf != need_of())
        if base in ("g", "nle"):
            return z3.And(z3.Not(zf), sf == need_of())
        if base in ("o",):
            return need_of()
        if base in ("no",):
            return z3.Not(need_of())
        raise _Partial(f"unsupported conditional jump j{base}")

    # ---- the success path ----
    def finish(self):
        sr = self.success_return
        if sr is None:
            return
        if "rax" not in self.regv:
            raise _Partial("the success path never defines the return register")
        ret = self.regv["rax"]
        if sr == "nonzero":
            self.constraints.append(ret != 0)
        elif sr == "zero":
            self.constraints.append(ret == 0)
        else:
            self.constraints.append(ret == self.z3.BitVecVal(int(sr), 64))

    # ---- one instruction ----
    def step(self, ins, x86):
        z3 = self.z3
        mn = ins.mnemonic
        if mn in _SKIP_MNEMONICS:
            return "continue"
        if mn in ("ret", "retn", "retf"):
            self.finish()
            return "stop"
        if mn in ("jmp", "call", "leave_call") or mn.startswith("loop") or mn in ("syscall", "int", "int3"):
            raise _Partial(f"unsupported control/complex instruction: {mn}")
        if mn[0] == "j":                         # a conditional jump
            ops = ins.operands
            if len(ops) != 1 or ops[0].type != x86.X86_OP_IMM:
                raise _Partial(f"unsupported jump form: {mn} {ins.op_str}")
            target = int(ops[0].imm)
            if self.code_lo <= target < self.code_hi:
                raise _Partial("an in-region jump (loop or forward skip): not straight-line")
            taken = self.jcc_taken(mn[1:])
            self.constraints.append(z3.Not(taken))   # the check must pass -> branch to failure not taken
            return "continue"
        handler = getattr(self, f"_op_{mn}", None)
        if handler is None:
            raise _Partial(f"unsupported instruction: {mn} {ins.op_str}")
        handler(ins, x86)
        return "continue"

    # ---- data-movement ----
    def _op_mov(self, ins, x86):
        dst, src = ins.operands
        v, t = self.op_rd(src, x86, want_bits=dst.size * 8)
        prop = t if dst.size >= (self.word // 8) else None
        self.write_op(dst, x86, v, prop)

    _op_movabs = _op_mov

    def _op_lea(self, ins, x86):
        dst, src = ins.operands
        if src.type != x86.X86_OP_MEM:
            raise _Partial("lea with a non-memory source")
        m = src.mem
        if m.segment != 0 or m.index != 0:
            raise _Partial("lea with a segment/index operand")
        if m.base == 0:
            self.write_op(dst, x86, self.z3.BitVecVal(int(m.disp), 64), None)
            return
        bname = self.md.reg_name(m.base)
        if bname is None or bname not in _REGMAP:
            raise _Partial(f"lea base register {bname}")
        canon = _REGMAP[bname][0]
        if canon not in self.regv:
            raise _Partial(f"lea through undefined register {bname}")
        val = self.regv[canon] + self.z3.BitVecVal(int(m.disp), 64)
        t0 = self.regt.get(canon)
        t = (t0[0], t0[1] + int(m.disp)) if t0 is not None else None
        self.write_op(dst, x86, val, t)

    def _movx(self, ins, x86, signed):
        dst, src = ins.operands
        v, _ = self.op_rd(src, x86)
        db = dst.size * 8
        sb = v.size()
        if sb < db:
            v = self.z3.SignExt(db - sb, v) if signed else self.z3.ZeroExt(db - sb, v)
        else:
            v = self._fit(v, db)
        self.write_op(dst, x86, v, None)

    def _op_movzx(self, ins, x86):
        self._movx(ins, x86, False)

    def _op_movsx(self, ins, x86):
        self._movx(ins, x86, True)

    def _op_movsxd(self, ins, x86):
        self._movx(ins, x86, True)

    # ---- sign-extend accumulators ----
    def _op_cdqe(self, ins, x86):
        self.reg_write("rax", self.z3.SignExt(32, self.reg_read("eax")), None)

    def _op_cwde(self, ins, x86):
        self.reg_write("eax", self.z3.SignExt(16, self.reg_read("ax")), None)

    def _op_cbw(self, ins, x86):
        self.reg_write("ax", self.z3.SignExt(8, self.reg_read("al")), None)

    # ---- ALU helpers ----
    def _ptr_adjust(self, mn, dst, src, x86, ta):
        if mn in ("add", "sub") and src.type == x86.X86_OP_IMM and ta is not None:
            k, off = ta
            return (k, off + (int(src.imm) if mn == "add" else -int(src.imm)))
        return None

    def _alu(self, ins, x86, mn):
        dst, src = ins.operands
        size = dst.size * 8
        a, ta = self.op_rd(dst, x86)
        b, _ = self.op_rd(src, x86, want_bits=size)
        a = self._fit(a, size)
        b = self._fit(b, size)
        if mn == "add":
            res, kind = a + b, "add"
        elif mn == "sub":
            res, kind = a - b, "sub"
        elif mn == "and":
            res, kind = a & b, "and"
        elif mn == "or":
            res, kind = a | b, "or"
        elif mn == "xor":
            res, kind = a ^ b, "xor"
        else:
            raise _Partial(f"unsupported ALU op {mn}")
        self.flags = (kind, a, b, res, size)
        self.write_op(dst, x86, res, self._ptr_adjust(mn, dst, src, x86, ta))

    def _op_add(self, ins, x86):
        self._alu(ins, x86, "add")

    def _op_sub(self, ins, x86):
        self._alu(ins, x86, "sub")

    def _op_and(self, ins, x86):
        self._alu(ins, x86, "and")

    def _op_or(self, ins, x86):
        self._alu(ins, x86, "or")

    def _op_xor(self, ins, x86):
        self._alu(ins, x86, "xor")

    def _op_cmp(self, ins, x86):
        dst, src = ins.operands
        size = dst.size * 8
        a, _ = self.op_rd(dst, x86)
        b, _ = self.op_rd(src, x86, want_bits=size)
        a, b = self._fit(a, size), self._fit(b, size)
        self.flags = ("sub", a, b, a - b, size)

    def _op_test(self, ins, x86):
        dst, src = ins.operands
        size = dst.size * 8
        a, _ = self.op_rd(dst, x86)
        b, _ = self.op_rd(src, x86, want_bits=size)
        a, b = self._fit(a, size), self._fit(b, size)
        self.flags = ("and", a, b, a & b, size)

    def _op_not(self, ins, x86):
        dst = ins.operands[0]
        v, _ = self.op_rd(dst, x86)
        self.write_op(dst, x86, ~v, None)   # NOT sets no flags

    def _op_neg(self, ins, x86):
        dst = ins.operands[0]
        size = dst.size * 8
        v, _ = self.op_rd(dst, x86)
        v = self._fit(v, size)
        res = -v
        self.flags = ("sub", self.z3.BitVecVal(0, size), v, res, size)
        self.write_op(dst, x86, res, None)

    def _op_inc(self, ins, x86):
        dst = ins.operands[0]
        size = dst.size * 8
        v, t = self.op_rd(dst, x86)
        v = self._fit(v, size)
        one = self.z3.BitVecVal(1, size)
        res = v + one
        self.flags = ("inc", v, one, res, size)
        self.write_op(dst, x86, res, None)

    def _op_dec(self, ins, x86):
        dst = ins.operands[0]
        size = dst.size * 8
        v, t = self.op_rd(dst, x86)
        v = self._fit(v, size)
        one = self.z3.BitVecVal(1, size)
        res = v - one
        self.flags = ("dec", v, one, res, size)
        self.write_op(dst, x86, res, None)

    def _shift(self, ins, x86, how):
        z3 = self.z3
        dst, cnt = ins.operands
        if cnt.type != x86.X86_OP_IMM:
            raise _Partial("variable (cl) shift count")
        size = dst.size * 8
        v, _ = self.op_rd(dst, x86)
        v = self._fit(v, size)
        n = int(cnt.imm) & (size - 1)
        nn = z3.BitVecVal(n, size)
        if how == "shl":
            res = v << nn
        elif how == "shr":
            res = z3.LShR(v, nn)
        elif how == "sar":
            res = v >> nn
        elif how == "rol":
            res = z3.RotateLeft(v, n)
        else:
            res = z3.RotateRight(v, n)
        self.flags = ("shift", v, nn, res, size)
        self.write_op(dst, x86, res, None)

    def _op_shl(self, ins, x86):
        self._shift(ins, x86, "shl")

    _op_sal = _op_shl

    def _op_shr(self, ins, x86):
        self._shift(ins, x86, "shr")

    def _op_sar(self, ins, x86):
        self._shift(ins, x86, "sar")

    def _op_rol(self, ins, x86):
        self._shift(ins, x86, "rol")

    def _op_ror(self, ins, x86):
        self._shift(ins, x86, "ror")

    def _op_imul(self, ins, x86):
        z3 = self.z3
        ops = ins.operands
        if len(ops) == 2:
            dst, src = ops
            size = dst.size * 8
            a, _ = self.op_rd(dst, x86)
            b, _ = self.op_rd(src, x86, want_bits=size)
            res = self._fit(a, size) * self._fit(b, size)
        elif len(ops) == 3:
            dst, src, imm = ops
            size = dst.size * 8
            b, _ = self.op_rd(src, x86)
            c, _ = self.op_rd(imm, x86, want_bits=size)
            res = self._fit(b, size) * self._fit(c, size)
        else:
            raise _Partial("one-operand imul (rdx:rax) not modelled")
        self.flags = ("mul", None, None, res, size)   # ZF/SF/CF/OF undefined -> a later jcc is _Partial
        self.write_op(dst, x86, res, None)

    # ---- stack ----
    def _op_push(self, ins, x86):
        w = self.word // 8
        if "rsp" not in self.regt or self.regt["rsp"] is None or self.regt["rsp"][0] != "stack":
            raise _Partial("push with no modelled stack pointer")
        off = self.regt["rsp"][1] - w
        v, t = self.op_rd(ins.operands[0], x86, want_bits=w * 8)
        self.stack[off] = (w, self._fit(v, w * 8), t)
        self.regv["rsp"] = self.regv["rsp"] - self.z3.BitVecVal(w, 64)
        self.regt["rsp"] = ("stack", off)

    def _op_pop(self, ins, x86):
        w = self.word // 8
        if "rsp" not in self.regt or self.regt["rsp"] is None or self.regt["rsp"][0] != "stack":
            raise _Partial("pop with no modelled stack pointer")
        off = self.regt["rsp"][1]
        cell = self.stack.get(off)
        if cell is None or cell[0] != w:
            raise _Partial("pop of an unwritten/mismatched stack slot")
        self.write_op(ins.operands[0], x86, cell[1], cell[2])
        self.regv["rsp"] = self.regv["rsp"] + self.z3.BitVecVal(w, 64)
        self.regt["rsp"] = ("stack", off + w)

    def _op_leave(self, ins, x86):
        if "rbp" not in self.regv or self.regt.get("rbp") is None:
            raise _Partial("leave with no modelled frame pointer")
        self.regv["rsp"] = self.regv["rbp"]
        self.regt["rsp"] = self.regt["rbp"]
        # pop rbp
        w = self.word // 8
        off = self.regt["rsp"][1]
        cell = self.stack.get(off)
        if cell is None or cell[0] != w:
            raise _Partial("leave: unwritten saved frame pointer")
        self.regv["rbp"] = self._fit(cell[1], 64) if cell[1].size() != 64 else cell[1]
        self.regt["rbp"] = cell[2]
        self.regv["rsp"] = self.regv["rsp"] + self.z3.BitVecVal(w, 64)
        self.regt["rsp"] = ("stack", off + w)


def _free_var_names(z3, exprs):
    """The names of every free (uninterpreted-constant) z3 variable reachable from `exprs`."""
    seen, out = set(), set()
    stack = list(exprs)
    while stack:
        e = stack.pop()
        try:
            eid = e.get_id()
        except Exception:  # noqa: BLE001 - a BoolVal/True literal
            continue
        if eid in seen:
            continue
        seen.add(eid)
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            out.add(e.decl().name())
            continue
        stack.extend(e.children())
    return out


def _cs_for(arch, bits):
    import capstone
    a = str(arch).lower()
    if a in ("amd64", "x86_64", "x86-64", "x64"):
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, 64
    if a in ("i386", "x86", "x86-32", "ia32"):
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32, 32
    raise ValueError(f"lift: unsupported architecture {arch!r} (x86/x86-64 only)")


def lift_linear(code, n_input, *, arch="amd64", bits=64, base=0, input_reg=None,
                max_insns=MAX_INSNS, charset=None, byte_bits=8, success_return="nonzero",
                timeout_ms=DEFAULT_TIMEOUT_MS, max_candidates=MAX_CANDIDATES):
    """Auto-lift a STRAIGHT-LINE x86/x86-64 check (capstone READ -> z3) and solve for the input bytes
    that make it pass. Returns a never-wrong Solution: UNIQUE -> plain() bytes (z3 proved the input is
    the only one), MULTIPLE -> candidate_values() (<= MAX_CANDIDATES, never plain), UNDERCONSTRAINED/
    UNSAT/TIMEOUT -> None, and PARTIAL -> None whenever the lift did not faithfully model every
    instruction/operand (an unsupported op, an undefined read, a non-input/unwritten memory access, an
    in-region jump, an undefined flag, ...). Nothing of the code is executed.

    code            the raw bytes of the straight-line region (a single function / basic region).
    n_input         the number of input bytes the check consumes (solved for, 1..MAX_BYTES).
    arch/bits       'amd64'/64 (default) or 'i386'/32. x86 only (capstone, in .venv).
    base            the virtual address `code` loads at (so in-region jump targets are recognised).
    input_reg       the register holding the input pointer at entry. Default: rdi (amd64). For i386 the
                    SysV cdecl first stack argument [esp+4] is used when None.
    charset         an optional range/iterable every input byte must fall in (see charset_constraints).
    success_return  the caller's model of "accepted": 'nonzero' (default: the routine returns true on a
                    good key), 'zero', an int the return value must equal, or None (assert nothing about
                    the return value -- use only when the branches alone pin the input).
    """
    z3 = _require_z3()
    try:
        import capstone
        from capstone import x86
    except Exception:  # noqa: BLE001
        return Solution(PARTIAL, [], [], detail="capstone is not available", reason="no-capstone")

    try:
        code = bytes(code)
    except (TypeError, ValueError) as exc:
        raise ValueError("lift_linear: code must be bytes-like") from exc
    try:
        base = int(base)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("lift_linear: base must be an integer address") from exc
    n = int(n_input)
    if not 1 <= n <= MAX_BYTES:
        raise ValueError(f"lift_linear: n_input {n} out of range 1..{MAX_BYTES}")
    width = int(byte_bits)
    if not 1 <= width <= MAX_BITS:
        raise ValueError(f"lift_linear: byte_bits {width} out of range 1..{MAX_BITS}")
    names = [f"in{i}" for i in range(n)]
    in_vars = [z3.BitVec(names[i], width) for i in range(n)]
    byte_decode = width if width == 8 else None

    cs_arch, mode, word = _cs_for(arch, bits)
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    insns = list(md.disasm(code, int(base)))
    if not insns:
        return Solution(PARTIAL, [], names, byte_bits=byte_decode,
                        detail="capstone decoded no instructions", reason="no-insns")

    lifter = _Lifter(z3, in_vars, word, md, int(base), int(base) + len(code), success_return)
    # entry state: the input pointer, the stack pointer, and (i386 cdecl) the stacked argument.
    if input_reg is None and word == 64:
        input_reg = "rdi"
    if input_reg is not None:
        if input_reg not in _REGMAP:
            raise ValueError(f"lift_linear: unknown input_reg {input_reg!r}")
        canon = _REGMAP[input_reg][0]
        lifter.regv[canon] = z3.BitVec("in_ptr", 64)
        lifter.regt[canon] = ("input", 0)
    lifter.regv["rsp"] = z3.BitVec("rsp0", 64)
    lifter.regt["rsp"] = ("stack", 0)
    if input_reg is None and word == 32:
        # SysV cdecl: [esp+0] is the return address, [esp+4] the first argument (the input pointer).
        lifter.stack[4] = (4, z3.Extract(31, 0, z3.BitVec("in_ptr", 64)), ("input", 0))

    try:
        for i, ins in enumerate(insns):
            if i >= max_insns:
                raise _Partial(f"over {max_insns} instructions")
            if lifter.step(ins, x86) == "stop":
                break
        else:
            # Fell off the end without a ret: the fall-through runs into whatever follows. If
            # capstone could not decode every byte of the region, the next executed bytes are a
            # truncated/undecodable instruction, so the straight-line model is not faithful.
            decoded_end = insns[-1].address + insns[-1].size
            if decoded_end < base + len(code):
                raise _Partial("undecodable trailing bytes on the fall-through path")
            lifter.finish()   # fell off the end of the region without a ret
    except _Partial as exc:
        return Solution(PARTIAL, [], names, byte_bits=byte_decode,
                        detail=f"partial lift: {exc}", reason=str(exc))

    # Soundness gate: the success constraints must reference ONLY the input bytes. Any other free
    # variable (an opaque caller register, the input pointer's own value, the stack base) would make the
    # answer depend on unmodelled state, so the uniqueness proof could not be trusted -> PARTIAL.
    leaked = _free_var_names(z3, lifter.constraints) - set(names)
    if leaked:
        return Solution(PARTIAL, [], names, byte_bits=byte_decode,
                        detail="the constraints depend on unmodelled state, so uniqueness is not sound",
                        reason=f"non-input free vars in constraints: {sorted(leaked)}")

    cons = list(lifter.constraints)
    if charset is not None:
        cons = cons + charset_constraints(in_vars, charset)
    return solve(in_vars, cons, timeout_ms=timeout_ms, max_candidates=max_candidates,
                 byte_bits=byte_decode, var_names=names)


def lift_elf(data, n_input, *, func=None, max_bytes=4096, **kwargs):
    """Convenience: locate a function in an ELF (by name or by integer virtual address, else the entry
    point) with pwn.read_elf, slice at most `max_bytes` of its code from the containing executable
    section, and lift_linear it. x86/x86-64 only; None when the bytes are not such an ELF or the function
    is not found. All lift_linear keyword options pass through (charset, success_return, input_reg, ...)."""
    if isinstance(data, (bytes, bytearray)):
        blob = bytes(data)
    else:
        try:
            blob = Path(data).read_bytes()
        except (OSError, TypeError, ValueError):
            return None
    if str(HERE) not in sys.path:
        sys.path.insert(1, str(HERE))
    try:
        import pwn as _pwn
    except Exception:  # noqa: BLE001
        return None
    info = _pwn.read_elf(blob)
    if info is None or info["arch"] not in ("i386", "amd64"):
        return None
    arch = info["arch"]
    bits = info["class"] or (64 if arch == "amd64" else 32)
    addr = None
    if func is None:
        addr = info.get("entry")
    elif isinstance(func, int):
        addr = func
    else:
        for name, a in info.get("functions", []):
            if name == func:
                addr = a
                break
    if addr is None:
        return None
    for _name, sec_addr, code in info.get("exec_sections", []):
        if sec_addr <= addr < sec_addr + len(code):
            start = addr - sec_addr
            region = code[start:start + max_bytes]
            if not region:
                return None
            return lift_linear(region, n_input, arch=arch, bits=bits, base=addr, **kwargs)
    return None


# ---------------------------------------------------------------------------- selftest + CLI

def _selftest() -> int:
    """A handful of tiny solves that prove the never-wrong boundary; no z3 answer is ever wrong."""
    import z3
    ok = True

    def show(label, cond):
        nonlocal ok
        ok = ok and cond
        print(f"{'ok  ' if cond else 'FAIL'} {label}")

    # UNIQUE keygen -> plain bytes
    sol = keygen(4, lambda x: [x[0] ^ 0xAA == 0xE1, x[1] ^ x[0] == (ord('3') ^ 0x4B),
                               x[2] + x[1] == (ord('y') + ord('3')) & 0xFF, x[3] == 0x21],
                 charset=printable(), timeout_ms=4000)
    show(f"UNIQUE keygen plain={sol.plain()!r}", sol.is_unique and sol.plain() == b"K3y!"
         and sol.candidate_values() == [])

    # Equation system over ints -> unique
    a, b = z3.Ints("a b")
    sol = solve([a, b], [a + b == 7, a - b == 1])
    show(f"UNIQUE int system {sol.plain()}", sol.is_unique and sol.plain() == {"a": 4, "b": 3})

    # MULTIPLE -> candidates, never plain
    x = z3.BitVec("x", 8)
    sol = solve([x], [z3.Or(x == 10, x == 20, x == 30)])
    show(f"MULTIPLE candidates={sol.candidate_values()}", sol.status == MULTIPLE
         and sol.plain() is None and sorted(sol.candidate_values()) == [10, 20, 30])

    # UNDERCONSTRAINED -> None
    sol = solve([x], [z3.ULT(x, 200)])
    show("UNDERCONSTRAINED -> None", sol.status == UNDERCONSTRAINED and sol.plain() is None
         and sol.candidate_values() == [])

    # UNSAT -> None
    sol = solve([x], [x == 1, x == 2])
    show("UNSAT -> None", sol.status == UNSAT and sol.plain() is None)

    # Disassembly READ (recon): cmp eax,0x1337 ; cmp eax,5 ; mov eax,0x2a
    imms = {imm for _a, _m, _o, imm in
            scan_immediates(b"\x3d\x37\x13\x00\x00\x83\xf8\x05\xb8\x2a\x00\x00\x00")}
    show(f"scan_immediates read {sorted(imms)}", {0x1337, 0x5, 0x2A} <= imms)

    # Straight-line lift (capstone -> z3): movzx eax,[rdi]; xor al,0x5a; cmp al,0x1b; jne fail;
    # movzx eax,[rdi+1]; cmp al,0x42; jne fail; mov eax,1; ret  -> UNIQUE input b'A' + b'B' = b'AB'
    lifted = lift_linear(
        b"\x0f\xb6\x07\x34\x5a\x3c\x1b\x75\x30\x0f\xb6\x47\x01\x3c\x42\x75\x30\xb8\x01\x00\x00\x00\xc3",
        2, timeout_ms=4000)
    show(f"lift_linear UNIQUE plain={lifted.plain()!r}",
         lifted.is_unique and lifted.plain() == b"AB" and lifted.candidate_values() == [])
    # An indexed memory access is not modelled -> PARTIAL -> no plain, no candidates
    part = lift_linear(b"\x0f\xb6\x04\x07\x3c\x41\x75\x20\xb8\x01\x00\x00\x00\xc3", 1)
    show(f"lift_linear PARTIAL -> None ({part.status})",
         part.status == PARTIAL and part.plain() is None and part.candidate_values() == [])

    print("ok" if ok else "FAILED")
    return 0 if ok else 1


def main(argv) -> int:
    if "--selftest" in argv:
        return _selftest()
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: symbolic.py --selftest | symbolic.py <elf>...   "
              "(READ cmp constants; solving is a Python API, see the module docstring)",
              file=sys.stderr)
        return 2
    seen = False
    for p in paths:
        rep = cmp_constants(p)
        if rep is None:
            print(f"- {p}: not an x86/x86-64 ELF with readable code")
            continue
        seen = True
        print(f"# {p}  {rep['arch']} ELF{rep['bits']}  (READ ONLY: constants for z3 constraints, "
              "nothing is executed)")
        for sec_name, imms in rep["sections"]:
            print(f"  [{sec_name}] {len(imms)} immediate(s):")
            for addr, mn, op_str, imm in imms[:40]:
                print(f"    {addr:#x}: {mn} {op_str}   imm={imm:#x} ({imm})")
            if len(imms) > 40:
                print(f"    ... and {len(imms) - 40} more")
    print("These constants are DATA to lift into z3 constraints; a value is plain only on a "
          "z3-proved UNIQUE model, and the flag is never derived here.")
    return 0 if seen else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
