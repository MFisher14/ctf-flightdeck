"""Spec-driven register-machine interpreter, worked-example conformance gate and N-round service handler (B-057).

"Implement the machine" challenges hand out a prose instruction-set specification with worked examples
and a service that sends a program plus an input tape per round and wants the machine's exact output,
quirks included, for N rounds; one wrong answer closes the session. Each time an agent rebuilt the same
three things: an interpreter, an example checker and a round client. This module is those three, driven
by a declarative spec file the agent writes from the prose (a `*.machine.toml` or `*.machine.json`):

    spec = load_spec(path)                 # SpecError names the dotted key that is wrong
    run(spec, program_text, inputs)        # RunResult(outputs, text, steps, registers, flags, halted)
    conformance(spec)                      # run every worked example: ConformanceReport
    gate(spec)                             # the report, or GateRefused unless every example passes
    RoundHandler(spec)                     # prompt -> answer for tools/netplay.run_loop
    play(spec, host, port)                 # gate, then drive the service through netplay: PlayResult
    solve(challenge_dir, profile, **opts)  # the engine entry: SolverResult

Nothing here calls a model and nothing here executes spec text as Python: an instruction's `do` is
parsed with `ast` and compiled, node by node, from a small whitelisted language (integers, the operand,
register and flag names, + - * // % & | ^ << >>, comparisons, and/or/not, `x if c else y`, `mem[i]`,
assignments, `if`, and the builtins in BUILTINS). The machine model: named registers of `word_bits`
bits with a wrap, saturate or trap overflow rule, optional flags with per-flag update formulas and a
per-instruction `sets` list, optional memory, data stack and call stack, labels and jumps, structured
`repeat` / `if` (with else) / `while` blocks, an input tape and an output list, and a fuel cap on
executed instructions. Division by zero, an input read past the end of the tape, an empty-stack pop and
a bad memory address stop the run (MachineTrap) unless `[quirks]` says what the machine does instead.

The gate is the point: `play` and `solve` refuse to contact a service until every worked example of the
spec reproduces byte for byte, and a spec with no examples is refused too. A round the handler cannot
parse, or one whose program traps or runs out of fuel, raises instead of sending a guess.

Usage: `python -m ctf machine init|check|run|play` (ctf/cli/machine.py); docs/toolkits/spec_machine.md
has the spec reference. Bytecode VMs with hand-written handlers are solvers/binary/vm_lifter.py.
"""
from __future__ import annotations

import ast
import json
import re
import textwrap
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

__all__ = [
    "MachineError", "SpecError", "ProgramError", "MachineTrap", "FuelExhausted", "FramingError",
    "GateRefused", "MachineSpec", "Example", "Framing", "Program", "RunResult", "Record",
    "ExampleResult", "ConformanceReport", "PlayResult", "RoundHandler", "BUILTINS", "TEMPLATE",
    "SPEC_PATTERNS", "ENGINE_ID", "parse_spec", "load_spec", "parse_program", "run", "render_output",
    "parse_inputs", "find_records", "conformance", "gate", "play", "find_specs", "write_template",
    "solve",
]

ENGINE_ID = "toolkits.spec_machine"
SPEC_PATTERNS = ("*.machine.toml", "*.machine.json")

MAX_SPEC_BYTES = 1 << 20          # a spec file
MAX_TEXT_BYTES = 8 << 20          # an examples file, a program, a buffered service round
MAX_PROGRAM_INSTRUCTIONS = 200_000
MAX_DO_NODES = 2000               # syntax nodes in one `do` / `cond` / `count` / `update`
MAX_CALL_DEPTH = 4096
MAX_SHIFT = 4096                  # a larger left-shift count has the same effect on any word
MAX_FUEL = 1_000_000_000
DEFAULT_FUEL = 1_000_000
DEFAULT_MAX_OUTPUT = 65_536

# name -> (argument count, returns a value). The whole call surface of the `do` language.
BUILTINS: dict[str, tuple[int, bool]] = {
    "input": (0, True),     # the next input word (quirks.input_eof past the end)
    "pop": (0, True),       # pop the data stack (quirks.pop_empty when empty)
    "s": (1, True),         # the word read as two's complement
    "u": (1, True),         # the word read as unsigned
    "tdiv": (2, True),      # division truncating toward zero (quirks.div_zero)
    "tmod": (2, True),      # remainder with the dividend's sign (quirks.mod_zero)
    "output": (1, False),   # append one word to the output
    "push": (1, False),     # push one word on the data stack
    "goto": (1, False),     # continue at an instruction index (a `label` operand reads as one)
    "call": (1, False),     # goto, remembering the next instruction
    "ret": (0, False),      # back to the instruction after the matching call
    "halt": (0, False),     # stop the run
}
_CONSTANTS = ("mask", "bits", "raw", "result")
_RESERVED = frozenset(BUILTINS) | frozenset(_CONSTANTS) | {"mem"}
_ARG_KINDS = ("reg", "imm", "val", "label")
_BLOCK_KINDS = ("repeat", "if", "while")
_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_INT = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|[0-9]+)\Z")


class MachineError(ValueError):
    """Base of every error this module raises."""


class SpecError(MachineError):
    """The spec is wrong; the message names the dotted key."""


class ProgramError(MachineError):
    """A program does not parse under the spec; the message names the line."""


class MachineTrap(MachineError):
    """A run stopped: a division by zero, a bad address or an overflow the spec gives no rule for."""


class FuelExhausted(MachineTrap):
    """The run executed `limits.fuel` instructions without finishing."""


class FramingError(MachineError):
    """An examples file or a service round does not match `[framing]`."""


class GateRefused(MachineError):
    """The spec does not reproduce every worked example, so nothing is played. `.report` has the detail."""

    def __init__(self, message: str, report: "ConformanceReport"):
        super().__init__(message)
        self.report = report


# --------------------------------------------------------------------------------------------------
# Spec model
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Example:
    name: str
    program: str
    inputs: tuple[int, ...]
    output: str


@dataclass(frozen=True)
class Framing:
    """How a program, its input and (in an examples file) its expected output are laid out in text."""
    program_start: str | None = None
    program_end: str | None = None
    program_re: re.Pattern | None = None
    input_prefix: str | None = None
    input_re: re.Pattern | None = None
    output_prefix: str | None = None
    output_re: re.Pattern | None = None
    prompt: str | None = None


@dataclass(frozen=True)
class Record:
    program: str
    input_text: str
    output_text: str | None


class _Op:
    __slots__ = ("name", "args", "run")

    def __init__(self, name, args, run):
        self.name, self.args, self.run = name, args, run


class _Block:
    __slots__ = ("name", "kind", "args", "expr")

    def __init__(self, name, kind, args, expr):
        self.name, self.kind, self.args, self.expr = name, kind, args, expr


class MachineSpec:
    """A validated, compiled spec. Build one with parse_spec() or load_spec()."""

    def __init__(self) -> None:
        self.name = "machine"
        self.source = "<spec>"
        self.bits = 16
        self.mask = 0xFFFF
        self.overflow = "wrap"
        self.signed = False
        self.registers: tuple[str, ...] = ()
        self.reg_init: tuple[int, ...] = ()
        self.flags: tuple[str, ...] = ()
        self.flag_init: tuple[int, ...] = ()
        self.mem_size = 0
        self.stack_size = 0
        self.quirks: dict[str, Any] = {}
        self.comment: tuple[str, ...] = ("#", ";")
        self.separators = ","
        self.case_sensitive = True
        self.label_suffix = ":"
        self.end_word = "end"
        self.else_word = "else"
        self.imm_prefix = ""
        self.out_format = "dec"
        self.out_width = 0
        self.out_prefix = ""
        self.out_separator = " "
        self.out_empty = ""
        self.fuel = DEFAULT_FUEL
        self.max_output = DEFAULT_MAX_OUTPUT
        self.ops: dict[str, _Op] = {}
        self.blocks: dict[str, _Block] = {}
        self.framing: Framing | None = None
        self.examples: tuple[Example, ...] = ()
        self.fit: Callable[[int], int] = lambda v: v
        self.wrap: Callable[[int], int] = lambda v: v


def _known(table: dict, allowed: Sequence[str], where: str) -> None:
    extra = sorted(str(k) for k in table if k not in allowed)
    if extra:
        raise SpecError(f"{where}: unknown key(s) {', '.join(extra)} (known: {', '.join(sorted(allowed))})")


def _table(data: dict, key: str, where: str) -> dict:
    v = data.get(key, {})
    if not isinstance(v, dict):
        raise SpecError(f"{where}{key}: must be a table")
    return v


def _int(table: dict, key: str, where: str, default: int, lo: int, hi: int) -> int:
    v = table.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise SpecError(f"{where}.{key}: must be an integer {lo}..{hi}; got {v!r}")
    return v


def _str(table: dict, key: str, where: str, default, choices: Sequence[str] | None = None):
    v = table.get(key, default)
    if v is default and default is None:
        return None
    if not isinstance(v, str):
        raise SpecError(f"{where}.{key}: must be a string; got {v!r}")
    if choices is not None and v not in choices:
        raise SpecError(f"{where}.{key}: must be one of {', '.join(choices)}; got {v!r}")
    return v


def _bool(table: dict, key: str, where: str, default: bool) -> bool:
    v = table.get(key, default)
    if not isinstance(v, bool):
        raise SpecError(f"{where}.{key}: must be true or false; got {v!r}")
    return v


def _quirk(table: dict, key: str, names: Sequence[str], default):
    """An integer the machine produces instead, or one of the named rules."""
    v = table.get(key, default)
    if isinstance(v, bool) or not (isinstance(v, int) or v in names):
        raise SpecError(f"quirks.{key}: must be an integer or one of {', '.join(names)}; got {v!r}")
    return v


def _make_fit(bits: int, overflow: str, signed: bool) -> tuple[Callable[[int], int], Callable[[int], int]]:
    """(fit, wrap): how a value becomes a word under the spec's overflow rule, and plain wrapping."""
    mask = (1 << bits) - 1
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, mask)
    if signed:
        def wrap(v: int) -> int:
            return ((v - lo) & mask) + lo
    else:
        def wrap(v: int) -> int:
            return v & mask
    if overflow == "wrap":
        return wrap, wrap
    if overflow == "saturate":
        return (lambda v: lo if v < lo else hi if v > hi else v), wrap

    def trap(v: int) -> int:
        if v < lo or v > hi:
            raise MachineTrap(f"value {v} does not fit a {'signed' if signed else 'unsigned'} {bits}-bit "
                              f"word and overflow = \"trap\"")
        return v
    return trap, wrap


# --------------------------------------------------------------------------------------------------
# The `do` language: ast in, closures out. Nothing is eval'ed.
# --------------------------------------------------------------------------------------------------

class _Machine:
    __slots__ = ("regs", "flags", "mem", "stack", "calls", "inp", "ip", "out", "raw", "result",
                 "jump", "restore", "halted", "pc", "frames")


class _Compiler:
    """Compiles one `do` body or one expression of one op, block or flag."""

    def __init__(self, spec: MachineSpec, args: tuple[tuple[str, str], ...], where: str):
        self.spec = spec
        self.args = {name: (i, kind) for i, (name, kind) in enumerate(args)}
        self.where = where
        self.locals: dict[str, int] = {}
        self.nodes = 0
        self.value_writes = 0
        self.reg = {n: i for i, n in enumerate(spec.registers)}
        self.flag = {n: i for i, n in enumerate(spec.flags)}

    def err(self, msg: str) -> SpecError:
        return SpecError(f"{self.where}: {msg}")

    def _parse(self, text: str, mode: str) -> ast.AST:
        if not isinstance(text, str) or not text.strip():
            raise self.err("must be a non-empty string")
        try:
            tree = ast.parse(textwrap.dedent(text).strip(), mode=mode)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
            raise self.err(f"does not parse: {str(e).splitlines()[0]}") from None
        for node in ast.walk(tree):
            self.nodes += 1
            if self.nodes > MAX_DO_NODES:
                raise self.err(f"too long (more than {MAX_DO_NODES} syntax nodes)")
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    if isinstance(t, ast.Name) and t.id.startswith("_") and t.id not in self.locals:
                        self.locals[t.id] = len(self.locals)
        return tree

    def expression(self, text: str):
        tree = self._parse(text, "eval")
        try:
            return self.expr(tree.body)
        except RecursionError:
            raise self.err("nested too deeply") from None

    def body(self, text: str):
        tree = self._parse(text, "exec")
        try:
            stmts = [self.stmt(s) for s in tree.body]
        except RecursionError:
            raise self.err("nested too deeply") from None
        return stmts, len(self.locals)

    # ---- expressions ----

    def expr(self, node: ast.AST):  # noqa: C901 - one branch per node type
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, bool):
                v = int(v)
            if not isinstance(v, int):
                raise self.err(f"only integer constants are allowed; got {node.value!r}")
            return lambda m, o, L: v
        if isinstance(node, ast.Name):
            return self.read_name(node.id)
        if isinstance(node, ast.UnaryOp):
            x = self.expr(node.operand)
            if isinstance(node.op, ast.USub):
                return lambda m, o, L: -x(m, o, L)
            if isinstance(node.op, ast.UAdd):
                return x
            if isinstance(node.op, ast.Invert):
                return lambda m, o, L: ~x(m, o, L)
            return lambda m, o, L: 0 if x(m, o, L) else 1          # ast.Not
        if isinstance(node, ast.BinOp):
            return self.binop(node)
        if isinstance(node, ast.BoolOp):
            parts = [self.expr(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return lambda m, o, L: 1 if all(p(m, o, L) for p in parts) else 0
            return lambda m, o, L: 1 if any(p(m, o, L) for p in parts) else 0
        if isinstance(node, ast.Compare):
            return self.compare(node)
        if isinstance(node, ast.IfExp):
            c, a, b = self.expr(node.test), self.expr(node.body), self.expr(node.orelse)
            return lambda m, o, L: a(m, o, L) if c(m, o, L) else b(m, o, L)
        if isinstance(node, ast.Call):
            return self.call(node, want_value=True)
        if isinstance(node, ast.Subscript):
            addr = self.mem_address(node)
            return lambda m, o, L: m.mem[addr(m, o, L)]
        raise self.err(f"{type(node).__name__} is not part of the instruction language")

    def binop(self, node: ast.BinOp):
        a, b = self.expr(node.left), self.expr(node.right)
        op = type(node.op)
        q = self.spec.quirks
        if op is ast.Add:
            return lambda m, o, L: a(m, o, L) + b(m, o, L)
        if op is ast.Sub:
            return lambda m, o, L: a(m, o, L) - b(m, o, L)
        if op is ast.Mult:
            return lambda m, o, L: a(m, o, L) * b(m, o, L)
        if op is ast.BitAnd:
            return lambda m, o, L: a(m, o, L) & b(m, o, L)
        if op is ast.BitOr:
            return lambda m, o, L: a(m, o, L) | b(m, o, L)
        if op is ast.BitXor:
            return lambda m, o, L: a(m, o, L) ^ b(m, o, L)
        if op is ast.FloorDiv:
            return _divider(a, b, lambda x, y: x // y, q["div_zero"], "division")
        if op is ast.Mod:
            return _divider(a, b, lambda x, y: x % y, q["mod_zero"], "remainder")
        if op in (ast.LShift, ast.RShift):
            smask, left = q["shift_mask"], op is ast.LShift

            def shift(m, o, L):
                x, n = a(m, o, L), b(m, o, L)
                if smask is not None:
                    n &= smask
                if n < 0:
                    raise MachineTrap(f"shift by a negative count ({n}); set quirks.shift_mask")
                return x << min(n, MAX_SHIFT) if left else x >> n
            return shift
        if op is ast.Div:
            raise self.err("`/` is not defined on words: use `//` (floor) or tdiv() (truncate)")
        raise self.err(f"operator {op.__name__} is not part of the instruction language")

    def compare(self, node: ast.Compare):
        table = {ast.Eq: lambda x, y: x == y, ast.NotEq: lambda x, y: x != y,
                 ast.Lt: lambda x, y: x < y, ast.LtE: lambda x, y: x <= y,
                 ast.Gt: lambda x, y: x > y, ast.GtE: lambda x, y: x >= y}
        tests = []
        for op in node.ops:
            if type(op) not in table:
                raise self.err(f"comparison {type(op).__name__} is not part of the instruction language")
            tests.append(table[type(op)])
        terms = [self.expr(node.left)] + [self.expr(c) for c in node.comparators]

        def run(m, o, L):
            left = terms[0](m, o, L)
            for test, term in zip(tests, terms[1:]):
                right = term(m, o, L)
                if not test(left, right):
                    return 0
                left = right
            return 1
        return run

    def mem_address(self, node: ast.Subscript):
        if not (isinstance(node.value, ast.Name) and node.value.id == "mem"):
            raise self.err("only `mem[...]` can be indexed")
        size = self.spec.mem_size
        if not size:
            raise self.err("uses mem[...] but the spec has no [memory] size")
        idx, rule = self.expr(node.slice), self.spec.quirks["mem_oob"]

        def address(m, o, L):
            a = idx(m, o, L)
            if 0 <= a < size:
                return a
            if rule == "wrap":
                return a % size
            raise MachineTrap(f"memory address {a} is outside 0..{size - 1}; set quirks.mem_oob")
        return address

    def read_name(self, name: str):
        if name in self.args:
            i, kind = self.args[name]
            if kind == "reg":
                return lambda m, o, L: m.regs[o[i]]
            if kind == "val":
                return lambda m, o, L: m.regs[o[i][1]] if o[i][0] else o[i][1]
            return lambda m, o, L: o[i]                           # imm, label
        if name in self.reg:
            r = self.reg[name]
            return lambda m, o, L: m.regs[r]
        if name in self.flag:
            f = self.flag[name]
            return lambda m, o, L: m.flags[f]
        if name in self.locals:
            s = self.locals[name]
            return lambda m, o, L: L[s]
        if name == "mask":
            v = self.spec.mask
            return lambda m, o, L: v
        if name == "bits":
            v = self.spec.bits
            return lambda m, o, L: v
        if name == "raw":
            return lambda m, o, L: m.raw
        if name == "result":
            return lambda m, o, L: m.result
        known = sorted(set(self.args) | set(self.reg) | set(self.flag) | set(_CONSTANTS))
        raise self.err(f"unknown name {name!r} (operands, registers, flags and constants here: "
                       f"{', '.join(known)}; a local starts with `_` and must be assigned)")

    # ---- statements ----

    def writer(self, target: ast.AST):
        fit, wrap = self.spec.fit, self.spec.wrap
        if isinstance(target, ast.Subscript):
            addr = self.mem_address(target)
            self.value_writes += 1

            def to_mem(m, o, L, v):
                m.raw = v
                m.result = m.mem[addr(m, o, L)] = fit(v)
            return to_mem
        if not isinstance(target, ast.Name):
            raise self.err("an assignment target is a register, an operand, a flag, a `_local` or mem[...]")
        name = target.id
        if name in self.args:
            i, kind = self.args[name]
            if kind in ("imm", "label"):
                raise self.err(f"operand {name!r} is {kind}: it cannot be assigned")
            self.value_writes += 1
            if kind == "reg":
                def to_reg(m, o, L, v):
                    m.raw = v
                    m.result = m.regs[o[i]] = fit(v)
                return to_reg

            def to_val(m, o, L, v):
                if not o[i][0]:
                    raise MachineTrap(f"operand {name!r} is an immediate here: it cannot be written")
                m.raw = v
                m.result = m.regs[o[i][1]] = fit(v)
            return to_val
        if name in self.reg:
            r = self.reg[name]
            self.value_writes += 1

            def to_named(m, o, L, v):
                m.raw = v
                m.result = m.regs[r] = fit(v)
            return to_named
        if name in self.flag:
            f = self.flag[name]

            def to_flag(m, o, L, v):
                m.flags[f] = 1 if v else 0
            return to_flag
        if name in self.locals:
            s = self.locals[name]
            self.value_writes += 1

            def to_local(m, o, L, v):
                L[s] = m.raw = v
                m.result = wrap(v)
            return to_local
        if name in _RESERVED:
            raise self.err(f"{name!r} is read-only")
        raise self.err(f"cannot assign to {name!r}: not an operand, a register or a flag "
                       f"(a local starts with `_`)")

    def stmt(self, node: ast.stmt):
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                raise self.err("one target per assignment")
            write, value = self.writer(node.targets[0]), self.expr(node.value)
            return lambda m, o, L: write(m, o, L, value(m, o, L))
        if isinstance(node, ast.AugAssign):
            both = ast.BinOp(left=_as_load(node.target), op=node.op, right=node.value)
            write, value = self.writer(node.target), self.binop(both)
            return lambda m, o, L: write(m, o, L, value(m, o, L))
        if isinstance(node, ast.If):
            test = self.expr(node.test)
            yes = [self.stmt(s) for s in node.body]
            no = [self.stmt(s) for s in node.orelse]

            def branch(m, o, L):
                for s in (yes if test(m, o, L) else no):
                    s(m, o, L)
            return branch
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return self.call(node.value, want_value=False)
        if isinstance(node, ast.Pass):
            return lambda m, o, L: None
        raise self.err(f"{type(node).__name__} is not a statement of the instruction language "
                       f"(assignments, `if`, and calls of {', '.join(sorted(BUILTINS))})")

    def call(self, node: ast.Call, want_value: bool):  # noqa: C901 - one branch per builtin
        if not isinstance(node.func, ast.Name) or node.func.id not in BUILTINS:
            raise self.err(f"only these can be called: {', '.join(sorted(BUILTINS))}")
        name = node.func.id
        argc, valued = BUILTINS[name]
        if node.keywords or len(node.args) != argc or any(isinstance(a, ast.Starred) for a in node.args):
            raise self.err(f"{name}() takes {argc} argument(s)")
        if want_value and not valued:
            raise self.err(f"{name}() has no value: use it as a statement")
        spec, q = self.spec, self.spec.quirks
        a = [self.expr(x) for x in node.args]
        fit = spec.fit
        if name in ("push", "pop") and not spec.stack_size:
            raise self.err(f"uses {name}() but the spec has no [stack] size")
        if name == "input":
            eof = q["input_eof"]

            def read(m, o, L):
                if m.ip < len(m.inp):
                    m.ip += 1
                    return m.inp[m.ip - 1]
                if eof == "trap":
                    raise MachineTrap("input read past the end of the tape; set quirks.input_eof")
                return eof
            return read
        if name == "pop":
            empty = q["pop_empty"]

            def pop(m, o, L):
                if m.stack:
                    return m.stack.pop()
                if empty == "trap":
                    raise MachineTrap("pop from an empty stack; set quirks.pop_empty")
                return empty
            return pop
        if name == "s":
            bits, mask = spec.bits, spec.mask
            half = 1 << (bits - 1)
            return lambda m, o, L: ((a[0](m, o, L) & mask) ^ half) - half
        if name == "u":
            mask = spec.mask
            return lambda m, o, L: a[0](m, o, L) & mask
        if name == "tdiv":
            return _divider(a[0], a[1], _tdiv, q["div_zero"], "division")
        if name == "tmod":
            return _divider(a[0], a[1], lambda x, y: x - y * _tdiv(x, y), q["mod_zero"], "remainder")
        if name == "output":
            cap = spec.max_output

            def output(m, o, L):
                if len(m.out) >= cap:
                    raise MachineTrap(f"more than limits.max_output = {cap} output words")
                m.out.append(fit(a[0](m, o, L)))
            return output
        if name == "push":
            size = spec.stack_size

            def push(m, o, L):
                if len(m.stack) >= size:
                    raise MachineTrap(f"stack overflow: more than stack.size = {size} words")
                m.stack.append(fit(a[0](m, o, L)))
            return push
        if name == "goto":
            def goto(m, o, L):
                m.jump = a[0](m, o, L)
            return goto
        if name == "call":
            def call(m, o, L):
                if len(m.calls) >= MAX_CALL_DEPTH:
                    raise MachineTrap(f"call depth over {MAX_CALL_DEPTH}")
                m.calls.append((m.pc + 1, list(m.frames)))
                m.jump = a[0](m, o, L)
            return call
        if name == "ret":
            def ret(m, o, L):
                if not m.calls:
                    raise MachineTrap("ret with no call to return to")
                m.jump, m.restore = m.calls.pop()
            return ret

        def halt(m, o, L):
            m.halted = True
        return halt


def _as_load(target: ast.AST) -> ast.AST:
    if isinstance(target, ast.Name):
        return ast.Name(id=target.id, ctx=ast.Load())
    if isinstance(target, ast.Subscript):
        return ast.Subscript(value=target.value, slice=target.slice, ctx=ast.Load())
    return target


def _tdiv(x: int, y: int) -> int:
    q = abs(x) // abs(y)
    return q if (x < 0) == (y < 0) else -q


def _divider(a, b, op, rule, what: str):
    def run(m, o, L):
        x, y = a(m, o, L), b(m, o, L)
        if y == 0:
            if rule == "trap":
                raise MachineTrap(f"{what} by zero; set quirks.{'div' if what == 'division' else 'mod'}_zero")
            return x if rule == "dividend" else rule
        return op(x, y)
    return run


# --------------------------------------------------------------------------------------------------
# Spec parsing
# --------------------------------------------------------------------------------------------------

_TOP = ("name", "word_bits", "overflow", "signed", "registers", "flags", "memory", "stack", "quirks",
        "syntax", "io", "limits", "ops", "blocks", "framing", "examples", "examples_files")


def _parse_args(raw, where: str, taken: set[str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list) or len(raw) > 8:
        raise SpecError(f"{where}.args: must be a list of at most 8 operands")
    out, seen = [], set()
    for i, item in enumerate(raw):
        if not isinstance(item, str):
            raise SpecError(f"{where}.args[{i}]: must be \"name:kind\" or a kind; got {item!r}")
        name, sep, kind = item.partition(":")
        if not sep:
            name, kind = "abcdefgh"[i], item
        if kind not in _ARG_KINDS:
            raise SpecError(f"{where}.args[{i}]: kind must be one of {', '.join(_ARG_KINDS)}; got {kind!r}")
        if not _IDENT.match(name) or name in _RESERVED:
            raise SpecError(f"{where}.args[{i}]: operand name {name!r} is not usable")
        if name in taken or name in seen:
            raise SpecError(f"{where}.args[{i}]: operand name {name!r} is also a register, a flag or "
                            f"another operand; pick another")
        seen.add(name)
        out.append((name, kind))
    return tuple(out)


def _names(raw, where: str, taken: set[str], lower: bool) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw or len(raw) > 4096:
        raise SpecError(f"{where}: must be a list of 1..4096 names")
    out = []
    for n in raw:
        if not isinstance(n, str) or not _IDENT.match(n) or n in _RESERVED:
            raise SpecError(f"{where}: {n!r} is not a usable name")
        if lower and n != n.lower():
            raise SpecError(f"{where}: {n!r} must be lower-case when syntax.case_sensitive = false")
        if n in taken:
            raise SpecError(f"{where}: {n!r} is named twice")
        taken.add(n)
        out.append(n)
    return tuple(out)


def _regex(table: dict, key: str) -> re.Pattern | None:
    v = _str(table, key, "framing", None)
    if v is None:
        return None
    try:
        rx = re.compile(v, re.M | re.S)
    except re.error as e:
        raise SpecError(f"framing.{key}: not a regular expression: {e}") from None
    if rx.groups < 1:
        raise SpecError(f"framing.{key}: needs one capture group (the text wanted)")
    return rx


def _parse_framing(table: dict) -> Framing:
    keys = ("program_start", "program_end", "program_re", "input_prefix", "input_re", "output_prefix",
            "output_re", "prompt")
    _known(table, keys, "framing")
    vals = {k: (_regex(table, k) if k.endswith("_re") else _str(table, k, "framing", None)) for k in keys}
    for k in keys:
        if isinstance(vals[k], str) and not vals[k]:
            raise SpecError(f"framing.{k}: must not be empty")
    markers = vals["program_start"] is not None and vals["program_end"] is not None
    if vals["program_re"] is not None:
        if vals["program_start"] is not None or vals["program_end"] is not None:
            raise SpecError("framing: give program_re or program_start + program_end, not both")
    elif not markers:
        raise SpecError("framing: needs program_start and program_end, or program_re")
    for a, b in (("input_prefix", "input_re"), ("output_prefix", "output_re")):
        if vals[a] is not None and vals[b] is not None:
            raise SpecError(f"framing: give {a} or {b}, not both")
    return Framing(**vals)


def parse_spec(data: dict, *, base: Path | None = None, source: str = "<spec>") -> MachineSpec:  # noqa: C901
    """Validate and compile a spec given as a mapping. `base` is where `examples_files` are resolved.

    Every problem is a SpecError naming the dotted key; unknown keys are errors, not ignored.
    """
    if not isinstance(data, dict):
        raise SpecError("the spec must be a table")
    _known(data, _TOP, "spec")
    spec = MachineSpec()
    spec.source = source
    spec.name = _str(data, "name", "spec", "machine")
    spec.bits = _int(data, "word_bits", "spec", 16, 1, 64)
    spec.mask = (1 << spec.bits) - 1
    spec.overflow = _str(data, "overflow", "spec", "wrap", ("wrap", "saturate", "trap"))
    spec.signed = _bool(data, "signed", "spec", False)
    spec.fit, spec.wrap = _make_fit(spec.bits, spec.overflow, spec.signed)

    syn = _table(data, "syntax", "")
    _known(syn, ("comment", "separators", "case_sensitive", "label_suffix", "end", "else", "imm_prefix"),
           "syntax")
    comment = syn.get("comment", ["#", ";"])
    if not isinstance(comment, list) or not all(isinstance(c, str) and c for c in comment):
        raise SpecError("syntax.comment: must be a list of non-empty strings")
    spec.comment = tuple(comment)
    spec.separators = _str(syn, "separators", "syntax", ",")
    spec.case_sensitive = _bool(syn, "case_sensitive", "syntax", True)
    spec.label_suffix = _str(syn, "label_suffix", "syntax", ":")
    spec.end_word = _str(syn, "end", "syntax", "end")
    spec.else_word = _str(syn, "else", "syntax", "else")
    spec.imm_prefix = _str(syn, "imm_prefix", "syntax", "")
    lower = not spec.case_sensitive

    taken: set[str] = set()
    reg = _table(data, "registers", "")
    _known(reg, ("names", "count", "prefix", "init"), "registers")
    if "names" in reg:
        if "count" in reg or "prefix" in reg:
            raise SpecError("registers: give names, or count (+ prefix), not both")
        spec.registers = _names(reg["names"], "registers.names", taken, lower)
    else:
        count = _int(reg, "count", "registers", 0, 1, 4096) if "count" in reg else 0
        if not count:
            raise SpecError("registers: needs names = [...] or count = N")
        prefix = _str(reg, "prefix", "registers", "r")
        spec.registers = _names([f"{prefix}{i}" for i in range(count)], "registers", taken, lower)
    init = reg.get("init", {})
    if not isinstance(init, dict):
        raise SpecError("registers.init: must be a table of register = value")
    _known(init, spec.registers, "registers.init")
    for name, v in init.items():
        if isinstance(v, bool) or not isinstance(v, int):
            raise SpecError(f"registers.init.{name}: must be an integer; got {v!r}")
    try:
        spec.reg_init = tuple(spec.fit(init.get(n, 0)) for n in spec.registers)
    except MachineTrap as e:
        raise SpecError(f"registers.init: {e}") from None

    flags = _table(data, "flags", "")
    spec.flags = _names(list(flags), "flags", taken, lower) if flags else ()
    flag_updates: dict[str, str] = {}
    flag_init = []
    for name in spec.flags:
        ft = flags[name]
        if not isinstance(ft, dict):
            raise SpecError(f"flags.{name}: must be a table")
        _known(ft, ("update", "init"), f"flags.{name}")
        flag_init.append(_int(ft, "init", f"flags.{name}", 0, 0, 1))
        if "update" in ft:
            flag_updates[name] = ft["update"]
    spec.flag_init = tuple(flag_init)

    mem = _table(data, "memory", "")
    _known(mem, ("size",), "memory")
    spec.mem_size = _int(mem, "size", "memory", 0, 1, 1 << 24) if mem else 0
    stack = _table(data, "stack", "")
    _known(stack, ("size",), "stack")
    spec.stack_size = _int(stack, "size", "stack", 0, 1, 1 << 24) if stack else 0

    qk = _table(data, "quirks", "")
    _known(qk, ("div_zero", "mod_zero", "shift_mask", "mem_oob", "input_eof", "pop_empty"), "quirks")
    spec.quirks = {
        "div_zero": _quirk(qk, "div_zero", ("trap", "dividend"), "trap"),
        "mod_zero": _quirk(qk, "mod_zero", ("trap", "dividend"), "trap"),
        "shift_mask": _int(qk, "shift_mask", "quirks", 0, 0, (1 << 64) - 1) if "shift_mask" in qk else None,
        "mem_oob": _str(qk, "mem_oob", "quirks", "trap", ("trap", "wrap")),
        "input_eof": _quirk(qk, "input_eof", ("trap",), "trap"),
        "pop_empty": _quirk(qk, "pop_empty", ("trap",), "trap"),
    }

    io = _table(data, "io", "")
    _known(io, ("format", "width", "prefix", "separator", "empty"), "io")
    spec.out_format = _str(io, "format", "io", "dec", ("dec", "signed", "hex", "char"))
    spec.out_width = _int(io, "width", "io", 0, 0, 64)
    spec.out_prefix = _str(io, "prefix", "io", "")
    spec.out_separator = _str(io, "separator", "io", "" if spec.out_format == "char" else " ")
    spec.out_empty = _str(io, "empty", "io", "")

    lim = _table(data, "limits", "")
    _known(lim, ("fuel", "max_output"), "limits")
    spec.fuel = _int(lim, "fuel", "limits", DEFAULT_FUEL, 1, MAX_FUEL)
    spec.max_output = _int(lim, "max_output", "limits", DEFAULT_MAX_OUTPUT, 1, 1 << 24)

    updates = {name: _Compiler(spec, (), f"flags.{name}.update").expression(text)
               for name, text in flag_updates.items()}
    flag_index = {n: i for i, n in enumerate(spec.flags)}

    ops = _table(data, "ops", "")
    blocks = _table(data, "blocks", "")
    if not ops:
        raise SpecError("ops: the spec defines no instruction")
    words = {spec.end_word, spec.else_word} if blocks else set()
    for group, table in (("ops", ops), ("blocks", blocks)):
        for name, body in table.items():
            where = f"{group}.{name}"
            if not isinstance(name, str) or not name or any(c.isspace() for c in name):
                raise SpecError(f"{where}: an instruction name is one word")
            if lower and name != name.lower():
                raise SpecError(f"{where}: must be lower-case when syntax.case_sensitive = false")
            if name in words or (group == "blocks" and name in ops):
                raise SpecError(f"{where}: the name is already an instruction or the block end/else word")
            if not isinstance(body, dict):
                raise SpecError(f"{where}: must be a table")
            args = _parse_args(body.get("args", []), where, taken)
            if group == "ops":
                _known(body, ("args", "do", "sets"), where)
                comp = _Compiler(spec, args, f"{where}.do")
                stmts, nloc = comp.body(body.get("do"))
                sets = body.get("sets", [])
                if not isinstance(sets, list) or len(set(map(str, sets))) != len(sets):
                    raise SpecError(f"{where}.sets: must be a list of distinct flag names")
                for f in sets:
                    if f not in updates:
                        raise SpecError(f"{where}.sets: {f!r} is not a flag with an `update` formula")
                if sets and not comp.value_writes:
                    raise SpecError(f"{where}: sets flags but its `do` assigns no value; the formulas read "
                                    f"`result` and `raw` (assign a `_local` to set them without a write)")
                spec.ops[name] = _Op(name, args, _op_runner(stmts, nloc, [(flag_index[f], updates[f])
                                                                         for f in sets]))
            else:
                _known(body, ("kind", "args", "cond", "count"), where)
                kind = _str(body, "kind", where, None, _BLOCK_KINDS)
                if kind is None:
                    raise SpecError(f"{where}.kind: must be one of {', '.join(_BLOCK_KINDS)}")
                key, other = ("count", "cond") if kind == "repeat" else ("cond", "count")
                if other in body:
                    raise SpecError(f"{where}.{other}: a {kind} block takes `{key}`")
                expr = _Compiler(spec, args, f"{where}.{key}").expression(body.get(key))
                spec.blocks[name] = _Block(name, kind, args, expr)

    if "framing" in data:
        spec.framing = _parse_framing(_table(data, "framing", ""))
    spec.examples = tuple(_parse_examples(spec, data, base))
    return spec


def _op_runner(stmts, nloc: int, updates):
    if not updates and len(stmts) == 1 and not nloc:
        only = stmts[0]
        return lambda m, o: only(m, o, ())

    def run(m, o):
        L = [0] * nloc
        for s in stmts:
            s(m, o, L)
        if updates:
            new = [(i, 1 if f(m, o, L) else 0) for i, f in updates]
            for i, v in new:
                m.flags[i] = v
    return run


def _parse_examples(spec: MachineSpec, data: dict, base: Path | None) -> list[Example]:
    out: list[Example] = []
    inline = data.get("examples", [])
    if not isinstance(inline, list):
        raise SpecError("examples: must be a list of tables ([[examples]])")
    for i, ex in enumerate(inline):
        where = f"examples[{i}]"
        if not isinstance(ex, dict):
            raise SpecError(f"{where}: must be a table")
        _known(ex, ("name", "program", "input", "output"), where)
        program = _str(ex, "program", where, None)
        output = _str(ex, "output", where, None)
        if program is None or output is None:
            raise SpecError(f"{where}: needs program and output")
        inputs = ex.get("input", [])
        if not isinstance(inputs, list) or any(isinstance(v, bool) or not isinstance(v, int) for v in inputs):
            raise SpecError(f"{where}.input: must be a list of integers")
        out.append(Example(_str(ex, "name", where, f"example {i + 1}"), program, tuple(inputs), output))
    files = data.get("examples_files", [])
    if not isinstance(files, list) or not all(isinstance(f, str) and f for f in files):
        raise SpecError("examples_files: must be a list of file paths")
    for rel in files:
        if spec.framing is None:
            raise SpecError("examples_files: needs [framing] to say how a file is laid out")
        # A spec may ship inside a challenge folder: its example files stay inside the spec's own folder.
        if Path(rel).is_absolute():
            raise SpecError(f"examples_files: {rel!r} is an absolute path; name a file in the spec's folder")
        if base is None:
            raise SpecError(f"examples_files: {rel!r} is relative and the spec has no folder")
        folder = Path(base).resolve()
        path = (folder / rel).resolve()
        if not path.is_relative_to(folder):
            raise SpecError(f"examples_files: {rel!r} leads outside the spec's folder {folder}")
        text =_read_text(path, f"examples_files: {rel}", MAX_TEXT_BYTES, SpecError)
        try:
            records = find_records(spec.framing, text, want_output=True)
            if not records:
                raise FramingError("the framing matched no example")
            for n, rec in enumerate(records, 1):
                out.append(Example(f"{path.name} #{n}", rec.program, parse_inputs(rec.input_text),
                                   rec.output_text or ""))
        except FramingError as e:
            raise SpecError(f"examples_files: {rel}: {e}") from None
    return out


def _read_text(path: Path, what: str, cap: int, error: type[MachineError]) -> str:
    try:
        if path.stat().st_size > cap:
            raise error(f"{what}: larger than {cap} bytes")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise error(f"{what}: cannot read {path}: {e.strerror or e}") from None


def load_spec(path: str | Path) -> MachineSpec:
    """Read a spec file: TOML, or JSON when the name ends in .json. SpecError on any problem."""
    path = Path(path)
    text = _read_text(path, "spec", MAX_SPEC_BYTES, SpecError)
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
        raise SpecError(f"{path}: not valid {'JSON' if path.suffix.lower() == '.json' else 'TOML'}: {e}") from None
    return parse_spec(data, base=path.parent, source=str(path))


# --------------------------------------------------------------------------------------------------
# Programs
# --------------------------------------------------------------------------------------------------

_OP, _OPEN, _ELSE, _END = 0, 1, 2, 3


class _Instr:
    __slots__ = ("kind", "defn", "ops", "line", "text", "a", "b")

    def __init__(self, kind, defn, ops, line, text):
        self.kind, self.defn, self.ops, self.line, self.text = kind, defn, ops, line, text
        self.a = self.b = -1          # open: end, else | else: end | end: open


@dataclass(frozen=True)
class Program:
    instructions: tuple
    labels: dict
    enclosing: tuple          # per instruction index (and one past the end): the innermost open block, or -1

    def __len__(self) -> int:
        return len(self.instructions)


def _parse_int(token: str) -> int | None:
    if len(token) > 80 or not _INT.match(token):
        return None
    body = token.lstrip("+-")
    base = {"0x": 16, "0b": 2, "0o": 8}.get(body[:2].lower(), 10)
    value = int(body, base)
    return -value if token[0] == "-" else value


def parse_program(spec: MachineSpec, source: str) -> Program:  # noqa: C901
    """Parse program text under the spec's syntax. ProgramError names the line and what is wrong."""
    if not isinstance(source, str):
        raise ProgramError("a program is text")
    if len(source) > MAX_TEXT_BYTES:
        raise ProgramError(f"program larger than {MAX_TEXT_BYTES} bytes")
    reg = {n: i for i, n in enumerate(spec.registers)}
    instrs: list[_Instr] = []
    labels: dict[str, int] = {}
    fixups: list[tuple[int, int, str, int, str]] = []
    opens: list[int] = []
    enclosing: list[int] = []
    sep = str.maketrans({c: " " for c in spec.separators})

    for lineno, raw in enumerate(source.splitlines(), 1):
        text = raw
        cut = min((text.find(c) for c in spec.comment if c in text), default=-1)
        if cut >= 0:
            text = text[:cut]
        if not spec.case_sensitive:
            text = text.lower()
        tokens = text.translate(sep).split()
        shown = raw.strip()

        def bad(msg: str) -> ProgramError:
            return ProgramError(f"line {lineno} `{shown}`: {msg}")

        if tokens and spec.label_suffix and tokens[0].endswith(spec.label_suffix) \
                and len(tokens[0]) > len(spec.label_suffix):
            label = tokens.pop(0)[:-len(spec.label_suffix)]
            if label in labels:
                raise bad(f"label {label!r} is defined twice")
            labels[label] = len(instrs)
        if not tokens:
            continue
        if len(instrs) >= MAX_PROGRAM_INSTRUCTIONS:
            raise bad(f"more than {MAX_PROGRAM_INSTRUCTIONS} instructions")
        word, rest = tokens[0], tokens[1:]
        here = len(instrs)
        if spec.blocks and word in (spec.end_word, spec.else_word):
            if rest:
                raise bad(f"`{word}` takes no operand")
            if not opens:
                raise bad(f"`{word}` with no open block")
            top = instrs[opens[-1]]
            enclosing.append(opens[-1])
            if word == spec.else_word:
                if top.defn.kind != "if" or top.b != -1:
                    raise bad("`else` belongs to an `if` block, once")
                top.b = here
                instrs.append(_Instr(_ELSE, None, (), lineno, shown))
            else:
                ins = _Instr(_END, None, (), lineno, shown)
                ins.a = opens.pop()
                top.a = here
                if top.b != -1:
                    instrs[top.b].a = here
                instrs.append(ins)
            continue
        defn = spec.ops.get(word) or spec.blocks.get(word)
        if defn is None:
            raise bad(f"unknown instruction {word!r}")
        if len(rest) != len(defn.args):
            want = " ".join(f"<{n}:{k}>" for n, k in defn.args)
            raise bad(f"{word} takes {len(defn.args)} operand(s) ({want or 'none'}); got {len(rest)}")
        operands: list[Any] = []
        for slot, ((name, kind), tok) in enumerate(zip(defn.args, rest)):
            if kind == "label":
                fixups.append((here, slot, tok, lineno, shown))
                operands.append(-1)
                continue
            imm = None
            if kind != "reg":
                body = tok[len(spec.imm_prefix):] if spec.imm_prefix and tok.startswith(spec.imm_prefix) else tok
                imm = _parse_int(body)
            if kind == "reg" or (kind == "val" and tok in reg):
                if tok not in reg:
                    raise bad(f"operand {name!r}: {tok!r} is not a register")
                operands.append((True, reg[tok]) if kind == "val" else reg[tok])
            elif imm is None:
                raise bad(f"operand {name!r}: {tok!r} is not {'a register or ' if kind == 'val' else ''}an integer")
            else:
                operands.append((False, imm) if kind == "val" else imm)
        enclosing.append(opens[-1] if opens else -1)
        is_block = word in spec.blocks
        instrs.append(_Instr(_OPEN if is_block else _OP, defn, operands, lineno, shown))
        if is_block:
            opens.append(here)

    if opens:
        top = instrs[opens[-1]]
        raise ProgramError(f"line {top.line} `{top.text}`: block is never closed with `{spec.end_word}`")
    for index, slot, tok, lineno, shown in fixups:
        if tok not in labels:
            raise ProgramError(f"line {lineno} `{shown}`: unknown label {tok!r}")
        instrs[index].ops[slot] = labels[tok]
    for ins in instrs:
        ins.ops = tuple(ins.ops)
    enclosing.append(-1)
    return Program(tuple(instrs), labels, tuple(enclosing))


# --------------------------------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class RunResult:
    outputs: tuple[int, ...]
    text: str                      # the outputs rendered under [io]
    steps: int                     # instructions executed (what `limits.fuel` caps)
    registers: dict
    flags: dict
    halted: bool                   # True when halt() ended the run, False when it ran off the end


def render_output(spec: MachineSpec, outputs: Sequence[int]) -> str:
    """The answer text for a run's output words, under the spec's [io] table."""
    if not outputs:
        return spec.out_empty
    fmt, width, mask = spec.out_format, spec.out_width, spec.mask
    half = 1 << (spec.bits - 1)
    parts = []
    for v in outputs:
        if fmt == "char":
            parts.append(chr(v & mask) if (v & mask) < 0x110000 else "�")
        elif fmt == "hex":
            parts.append(spec.out_prefix + format(v & mask, "x").zfill(width))
        else:
            n = ((v & mask) ^ half) - half if fmt == "signed" else v
            parts.append(spec.out_prefix + ("-" if n < 0 else "") + str(abs(n)).zfill(width))
    return spec.out_separator.join(parts)


def run(spec: MachineSpec, program: str | Program, inputs: Sequence[int] = (), *, fuel: int | None = None,
        trace: Callable[[int, str, dict, dict], None] | None = None) -> RunResult:  # noqa: C901
    """Run one program on one input tape.

    `fuel` (default `limits.fuel`) caps the instructions executed; FuelExhausted past it. `trace`, when
    given, is called after every executed instruction as trace(line, text, registers, flags). A
    MachineTrap names the source line it happened on.
    """
    prog = program if isinstance(program, Program) else parse_program(spec, program)
    instrs, enclosing, n = prog.instructions, prog.enclosing, len(prog.instructions)
    limit = spec.fuel if fuel is None else fuel
    m = _Machine()
    m.regs, m.flags = list(spec.reg_init), list(spec.flag_init)
    m.mem, m.stack, m.calls = [0] * spec.mem_size, [], []
    m.inp, m.ip, m.out = list(inputs), 0, []
    m.raw = m.result = 0
    m.jump = m.restore = None
    m.halted = False
    frames: list[list[int]] = []
    m.frames = frames
    pc = steps = 0
    no_locals: tuple = ()

    while pc < n and not m.halted:
        if steps >= limit:
            raise FuelExhausted(f"fuel exhausted: {limit} instructions executed, stopped at line "
                                f"{instrs[pc].line} `{instrs[pc].text}` (raise limits.fuel if the program is "
                                f"meant to run this long)")
        steps += 1
        ins = instrs[pc]
        kind = ins.kind
        try:
            if kind == _OP:
                m.pc = pc
                ins.defn.run(m, ins.ops)
                if m.jump is None:
                    pc += 1
                else:
                    target, m.jump = m.jump, None
                    if not 0 <= target <= n:
                        raise MachineTrap(f"jump to instruction {target}, outside the program (0..{n})")
                    if m.restore is not None:                 # ret: back into the caller's blocks
                        frames[:] = m.restore
                        m.restore = None
                    else:
                        while frames and not frames[-1][0] < target <= instrs[frames[-1][0]].a:
                            frames.pop()
                        if enclosing[target] != (frames[-1][0] if frames else -1):
                            raise MachineTrap("jump into a block that is not running")
                    pc = target
            elif kind == _OPEN:
                value = ins.defn.expr(m, ins.ops, no_locals)
                block = ins.defn.kind
                if block == "repeat":
                    if value > 0:
                        frames.append([pc, value])
                        pc += 1
                    else:
                        pc = ins.a + 1
                elif value:
                    frames.append([pc, 0])
                    pc += 1
                elif block == "if" and ins.b != -1:
                    frames.append([pc, 0])
                    pc = ins.b + 1
                else:
                    pc = ins.a + 1
            elif kind == _ELSE:                               # the true branch ran into its else
                frames.pop()
                pc = ins.a + 1
            else:
                frame = frames[-1]
                opener = instrs[frame[0]]
                block = opener.defn.kind
                if block == "repeat":
                    frame[1] -= 1
                    again = frame[1] > 0
                elif block == "while":
                    again = bool(opener.defn.expr(m, opener.ops, no_locals))
                else:
                    again = False
                if again:
                    pc = frame[0] + 1
                else:
                    frames.pop()
                    pc += 1
        except MachineTrap as e:
            raise type(e)(f"line {ins.line} `{ins.text}`: {e}") from None
        if trace is not None:
            trace(ins.line, ins.text, dict(zip(spec.registers, m.regs)), dict(zip(spec.flags, m.flags)))

    return RunResult(tuple(m.out), render_output(spec, m.out), steps, dict(zip(spec.registers, m.regs)),
                     dict(zip(spec.flags, m.flags)), m.halted)


# --------------------------------------------------------------------------------------------------
# Framing: programs, inputs and expected outputs in an examples file or a service round
# --------------------------------------------------------------------------------------------------

def parse_inputs(text: str) -> tuple[int, ...]:
    """The integers of an input line: separated by blanks or commas; decimal, 0x, 0b or 0o."""
    out = []
    for tok in text.replace(",", " ").split():
        v = _parse_int(tok)
        if v is None:
            raise FramingError(f"input word {tok!r} is not an integer")
        out.append(v)
    return tuple(out)


def _group(match: re.Match) -> str:
    return match.group(1) or ""


def _field(span: str, prefix: str | None, rx: re.Pattern | None) -> str | None:
    """A prefixed line's remainder, or a regex's first group, inside one record's text, outer blanks
    removed. None = absent."""
    if rx is not None:
        hit = rx.search(span)
        return _group(hit).strip() if hit else None
    if prefix is None:
        return None
    for line in span.splitlines():
        if line.lstrip().startswith(prefix):
            return line.lstrip()[len(prefix):].strip()
    return None


def find_records(framing: Framing, text: str, *, want_output: bool) -> list[Record]:
    """Every complete program in `text` with its input (and expected output when `want_output`).

    A program whose end marker has not arrived yet is left out (a service may still be sending it). A
    program whose input is declared in the framing but missing, or (with `want_output`) whose expected
    output is missing, is a FramingError.
    """
    found: list[tuple[str, int, int]] = []          # program text, where its tail starts, where it began
    if framing.program_re is not None:
        for hit in framing.program_re.finditer(text):
            found.append((_group(hit), hit.end(), hit.start()))
    else:
        lines = text.splitlines(keepends=True)
        offsets, at = [], 0
        for ln in lines:
            offsets.append(at)
            at += len(ln)
        offsets.append(at)
        i = 0
        while i < len(lines):
            if lines[i].strip() != framing.program_start:
                i += 1
                continue
            j = i + 1
            while j < len(lines) and lines[j].strip() != framing.program_end:
                j += 1
            if j >= len(lines):
                break                                # unterminated: not complete yet
            found.append(("".join(lines[i + 1:j]), offsets[j + 1], offsets[i]))
            i = j + 1
    records = []
    for k, (program, tail, _start) in enumerate(found):
        span = text[tail:found[k + 1][2]] if k + 1 < len(found) else text[tail:]
        n = k + 1
        input_text = _field(span, framing.input_prefix, framing.input_re)
        if input_text is None:
            if framing.input_prefix is not None or framing.input_re is not None:
                raise FramingError(f"program {n} has no input (the framing declares one)")
            input_text = ""
        output_text = None
        if want_output:
            output_text = _field(span, framing.output_prefix, framing.output_re)
            if output_text is None:
                raise FramingError(f"program {n} has no expected output (framing.output_prefix / output_re)")
        records.append(Record(program, input_text, output_text))
    return records


# --------------------------------------------------------------------------------------------------
# Conformance gate
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ExampleResult:
    index: int                     # 1-based
    name: str
    ok: bool
    expected: str
    got: str | None                # None when the run raised
    error: str | None


@dataclass(frozen=True)
class ConformanceReport:
    results: tuple[ExampleResult, ...]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def failures(self) -> tuple[ExampleResult, ...]:
        return tuple(r for r in self.results if not r.ok)

    @property
    def ok(self) -> bool:
        """Every example passed, and there was at least one."""
        return self.total > 0 and self.passed == self.total

    def summary(self) -> str:
        return f"{self.passed}/{self.total} worked examples reproduce"


def conformance(spec: MachineSpec, *, fuel: int | None = None) -> ConformanceReport:
    """Run every worked example of the spec and compare its output text exactly (outer blanks aside)."""
    results = []
    for i, ex in enumerate(spec.examples, 1):
        expected = ex.output.strip()
        try:
            got = run(spec, ex.program, ex.inputs, fuel=fuel).text.strip()
        except (ProgramError, MachineTrap) as e:
            results.append(ExampleResult(i, ex.name, False, expected, None, f"{type(e).__name__}: {e}"))
            continue
        results.append(ExampleResult(i, ex.name, got == expected, expected, got, None))
    return ConformanceReport(tuple(results))


def gate(spec: MachineSpec, *, fuel: int | None = None) -> ConformanceReport:
    """The conformance report when every worked example passes; GateRefused otherwise (also for none)."""
    report = conformance(spec, fuel=fuel)
    if not report.total:
        raise GateRefused(f"{spec.source}: no worked examples, so nothing proves the spec: add [[examples]] "
                          f"or examples_files before playing", report)
    if not report.ok:
        first = report.failures[0]
        detail = first.error or f"expected {first.expected!r}, got {first.got!r}"
        raise GateRefused(f"{spec.source}: {report.summary()}; refusing to play. First failure: "
                          f"{first.name}: {detail}", report)
    return report


# --------------------------------------------------------------------------------------------------
# The service half: a netplay handler and the gated play
# --------------------------------------------------------------------------------------------------

class RoundHandler:
    """`prompt -> answer` for tools/netplay.run_loop: the last complete program of a round, run.

    Text is buffered until the service's prompt marker (`framing.prompt`) arrives, so a round split
    over several reads is answered once, whole. Text with no marker yet returns None (run_loop keeps
    reading). A marker with no program in front of it, a program that does not parse, a trap and an
    exhausted fuel all raise: no guess is ever sent. Build one through gate()/play(), not before the
    examples pass.
    """

    def __init__(self, spec: MachineSpec, *, fuel: int | None = None, transcript: str | Path | None = None):
        if spec.framing is None or not spec.framing.prompt:
            raise SpecError(f"{spec.source}: [framing] with `prompt` (what the service prints when it waits "
                            f"for the answer) is needed to answer a service")
        self.spec, self.fuel = spec, fuel
        self.transcript = Path(transcript) if transcript else None
        self.rounds = 0
        self.last_text = ""            # what the service sent since the last answered round
        self._pending = ""

    def __call__(self, prompt: str) -> str | None:
        framing = self.spec.framing
        text = self._pending + prompt
        if framing.prompt not in text:
            if len(text) > MAX_TEXT_BYTES:
                raise FramingError(f"{MAX_TEXT_BYTES} bytes received without the prompt marker {framing.prompt!r}")
            self._pending = self.last_text = text
            return None
        self._pending = self.last_text = ""
        text = text[:text.rindex(framing.prompt)]
        records = find_records(framing, text, want_output=False)
        if not records:
            raise FramingError(f"the service is waiting ({framing.prompt!r} seen) but the framing found no "
                               f"complete program in the round")
        record = records[-1]
        answer = run(self.spec, record.program, parse_inputs(record.input_text), fuel=self.fuel).text
        self.rounds += 1
        if self.transcript is not None:
            with self.transcript.open("a", encoding="utf-8") as fh:
                fh.write(f"{text}{framing.prompt} {answer}\n")
        return answer


@dataclass(frozen=True)
class PlayResult:
    flag: str | None
    rounds: int                    # rounds answered
    report: ConformanceReport
    last_text: str                 # the last text the service sent that was not answered (its verdict)


def _netplay():
    """This checkout's tools/netplay.py, always by path: a flat `import netplay` would take whatever
    netplay.py sits first on sys.path (under `python -m`, the current folder, which may be a challenge
    folder). An already imported module is reused only when it is that same file."""
    import sys
    from ctf import packs, paths
    path = (paths.repo_root() / "tools" / "netplay.py").resolve()
    loaded = sys.modules.get("netplay")
    if loaded is not None and getattr(loaded, "__file__", None) and Path(loaded.__file__).resolve() == path:
        return loaded
    return packs.load_module("spec_machine_netplay", path, pack="tools/netplay")


def play(spec: MachineSpec, host: str, port: int, *, profile=None, timeout: float = 10.0, quiet: float = 0.3,
         max_rounds: int = 400, transcript: str | Path | None = None, fuel: int | None = None) -> PlayResult:
    """Gate, then answer the service at host:port round by round until it sends a flag or closes.

    Order: the conformance gate (GateRefused), the handler's framing check (SpecError), the live-service
    scope check (ctf.scope.OutOfScope), and only then a connection. A round that cannot be answered
    raises its MachineError with the connection closed. Nothing is submitted: the flag is returned.
    """
    report = gate(spec, fuel=fuel)
    handler = RoundHandler(spec, fuel=fuel, transcript=transcript)
    netplay = _netplay()
    if profile is not None:
        from ctf import scope
        scope.check_host(host, port, what=f"spec_machine target {host}:{port}", profile=profile)
    conn = netplay.connect(host, port, timeout=timeout, prefer_pwntools=False)
    try:
        flag = netplay.run_loop(conn, handler, delims=[spec.framing.prompt.encode()], timeout=timeout,
                                quiet=quiet, max_rounds=max_rounds)
    except RuntimeError as e:
        if isinstance(e.__cause__, MachineError):
            raise e.__cause__ from None
        raise
    finally:
        conn.close()
    return PlayResult(flag, handler.rounds, report, handler.last_text[-2000:])


# --------------------------------------------------------------------------------------------------
# Scaffold and engine entry
# --------------------------------------------------------------------------------------------------

TEMPLATE = '''\
# A machine spec for solvers/toolkits/spec_machine.py (python -m ctf machine check|run|play).
# Fill it in from the challenge's specification; reference: docs/toolkits/spec_machine.md.
# This starter is a complete 16-bit machine with its own worked examples: edit it, do not trust it.
name = "demo16"
word_bits = 16            # register width; every write is brought into range by `overflow`
overflow = "wrap"         # wrap | saturate | trap
signed = false            # true: words are two's complement values
# examples_files = ["examples.txt"]   # the handout's worked examples, parsed with [framing] (keep above the tables)

[registers]
count = 8                 # r0..r7  (or: names = ["a", "b", "acc"])
prefix = "r"

[flags.z]                 # a flag and how an instruction that lists it in `sets` updates it
update = "result == 0"
[flags.c]
update = "raw > mask or raw < 0"

[quirks]                  # what the machine does where others would stop; leave one out to trap
div_zero = 65535          # an integer, "dividend" or "trap"
mod_zero = "dividend"
shift_mask = 15           # the shift count is ANDed with this
input_eof = 65535         # what `input()` gives past the end of the tape

[io]
format = "dec"            # dec | signed | hex | char
separator = " "

[limits]
fuel = 1000000            # instructions one run may execute

# One table per instruction. args are "name:kind"; kinds: reg, imm, val (reg or imm), label.
# `do` is assignments, `if`, and calls of: input pop s u tdiv tmod output push goto call ret halt.
[ops.set]
args = ["d:reg", "v:imm"]
do = "d = v"
[ops.mov]
args = ["d:reg", "x:reg"]
do = "d = x"
[ops.add]
args = ["d:reg", "x:reg", "y:reg"]
do = "d = x + y"
sets = ["z", "c"]
[ops.sub]
args = ["d:reg", "x:reg", "y:reg"]
do = "d = x - y"
sets = ["z", "c"]
[ops.div]
args = ["d:reg", "x:reg", "y:reg"]
do = "d = x // y"
[ops.mod]
args = ["d:reg", "x:reg", "y:reg"]
do = "d = x % y"
[ops.shl]
args = ["d:reg", "x:reg", "y:reg"]
do = "d = x << y"
[ops.in]
args = ["d:reg"]
do = "d = input()"
[ops.out]
args = ["x:reg"]
do = "output(x)"
[ops.jnz]
args = ["t:label"]
do = "if not z: goto(t)"

# Structured blocks, closed by `end` (syntax.end). kinds: repeat (count), if (cond, with `else`), while (cond).
[blocks.rep]
kind = "repeat"
args = ["n:val"]
count = "n"
[blocks.ifz]
kind = "if"
args = ["x:reg"]
cond = "x == 0"

# How a program, its input and the expected output sit in an examples file and in a service round.
[framing]
program_start = "PROGRAM"
program_end = "."
input_prefix = "INPUT"
output_prefix = "OUTPUT"   # examples files only
prompt = "OUTPUT>"         # what the service prints when it waits for the answer

[[examples]]
name = "sum the tape three times over, wrapping"
program = """
in r1
in r2
rep 3
  add r0 r0 r1
  add r0 r0 r2
end
out r0
"""
input = [40000, 2]
output = "54470"

[[examples]]
name = "division by zero and a read past the tape"
program = """
in r1
div r2 r1 r3
mod r4 r1 r3
in r5
out r2
out r4
out r5
"""
input = [7]
output = "65535 7 65535"

[[examples]]
name = "count down with a flag and a jump"
program = """
set r1 3
set r2 1
loop: out r1
sub r1 r1 r2
jnz loop
ifz r1
  out r2
else
  out r1
end
"""
output = "3 2 1 1"
'''


def write_template(path: str | Path) -> Path:
    """Write the starter spec to `path` (a folder gets `machine.machine.toml`). Never overwrites."""
    path = Path(path)
    if path.is_dir():
        path = path / "machine.machine.toml"
    if path.exists():
        raise FileExistsError(f"{path} exists; not overwriting it")
    path.write_text(TEMPLATE, encoding="utf-8")
    return path


def find_specs(challenge_dir: str | Path) -> list[Path]:
    """Spec files (SPEC_PATTERNS) under a challenge folder, hidden folders left out, sorted."""
    root = Path(challenge_dir)
    hits = {p for pat in SPEC_PATTERNS for p in root.rglob(pat)
            if p.is_file() and not any(part.startswith(".") for part in p.relative_to(root).parts)}
    return sorted(hits)


def solve(challenge_dir, profile, *, spec: str | None = None, host: str | None = None, port: int | None = None,
          timeout: float = 10.0, max_rounds: int = 400, fuel: int | None = None, **_opts):
    """Engine entry: check the challenge's machine spec against its worked examples, then (with a
    `host` and `port`) play the service.

    `blocked`: no spec file yet (an agent writes it from the prose specification), several and no
    `spec` option, a spec that does not load, or a service outside the event's scope. `unsure`: the
    spec does not reproduce every worked example (each failure is evidence) or a round could not be
    answered; nothing more is sent. `none`: the examples pass and no service was named, or the
    service closed without a flag. `solved`: the service sent a value in the event flag format.
    """
    from ctf import flagfmt, scope
    from ctf.result import Evidence, SolverResult

    root = Path(challenge_dir)

    def result(status: str, notes: str, flags=(), evidence=()):
        return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                            notes=notes)

    if spec is not None:
        path = Path(spec) if Path(spec).is_absolute() else root / spec
    else:
        found = find_specs(root)
        if not found:
            return result("blocked", f"no machine spec ({' or '.join(SPEC_PATTERNS)}) under {root}: write one "
                                     f"from the challenge's specification (`python -m ctf machine init {root}` "
                                     f"gives a starter; docs/toolkits/spec_machine.md)")
        if len(found) > 1:
            names = ", ".join(str(p.relative_to(root)) for p in found)
            return result("blocked", f"several machine specs under {root} ({names}): pass --opt spec=<file>")
        path = found[0]
    try:
        machine = load_spec(path)
    except SpecError as e:
        return result("blocked", f"the machine spec does not load: {e}")
    try:
        shown = str(path.relative_to(root))
    except ValueError:
        shown = path.name
    report = conformance(machine, fuel=fuel)
    if not report.ok:
        evidence = [Evidence("conformance", f"{r.name}: " + (r.error or f"expected {r.expected!r}, got {r.got!r}"),
                             path=shown) for r in report.failures[:20]]
        why = "it has no worked examples" if not report.total else report.summary()
        return result("unsure", f"conformance gate closed: {why}; not playing until every example passes",
                      evidence=evidence)
    passed = Evidence("conformance", report.summary(), path=shown)
    if (host is None) != (port is None):
        missing, given = ("port", f"host={host!r}") if port is None else ("host", f"port={port!r}")
        return result("blocked", f"half a service target: {given} was given without a {missing}; pass both "
                                 f"(--opt host=... --opt port=...) or neither", evidence=[passed])
    if host is None:
        return result("none", f"{report.summary()}; no service named. Play it with `python -m ctf machine play "
                              f"{shown} HOST PORT` (or --opt host=... --opt port=...)", evidence=[passed])
    if not isinstance(host, str) or isinstance(port, bool) or not isinstance(port, int):
        return result("blocked", f"host must be a string and port an integer; got {host!r}, {port!r}")
    log = root / "recon" / "spec_machine" / "session.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        played = play(machine, host, port, profile=profile, timeout=timeout, max_rounds=max_rounds,
                      transcript=log, fuel=fuel)
    except scope.OutOfScope as e:
        return result("blocked", f"the service is outside the event's live-service scope: {e}", evidence=[passed])
    except MachineError as e:
        return result("unsure", f"stopped without answering a round ({type(e).__name__}: {e}); nothing was "
                                f"guessed. Transcript: {log.relative_to(root)}", evidence=[passed])
    wire = Evidence("wire", f"answered {played.rounds} round(s) of {host}:{port}", path=str(log.relative_to(root)))
    flags = flagfmt.find_flags(played.flag, profile) if played.flag else []
    if flags:
        return result("solved", f"{report.summary()}; the service sent the flag after {played.rounds} round(s)",
                      flags=flags, evidence=[passed, wire])
    if played.flag:
        return result("candidate", f"{report.summary()}; after {played.rounds} round(s) the service sent a value "
                                   f"that is a flag for the running event but not for this profile",
                      flags=[played.flag], evidence=[passed, wire])
    tail = " ".join(played.last_text.split())[-200:]
    return result("none", f"{report.summary()}; answered {played.rounds} round(s) and the service sent no flag. "
                          f"Its last words: {tail!r}", evidence=[passed, wire])
