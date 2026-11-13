#!/usr/bin/env python3
"""Dead-code constant extractor: constants hidden in unreachable blocks of a stack program (B-055).

Some esolang / bytecode challenges never *print* their flag: the bytes are pushed and emitted in a
block that control flow can never reach -- after an unconditional jump, past a halt, or behind a
guard that is always false -- so running the program shows nothing and the flag only falls out of a
static read of the dead code (PINK challenge 28). This module is that static read.

It works on a tiny, explicit stack bytecode (one instruction per line) so the control-flow graph is
unambiguous and the analysis is exact, not a guess:

    push N        push the integer N
    emit          output the top of stack as one byte (its value & 0xFF), pop it
    emitn         output the decimal text of the top of stack, pop it
    dup add sub   stack arithmetic (informational: the extractor tracks push/emit, not full data flow)
    jmp L         unconditional jump to label L
    jz L / jnz L  pop; branch to L when the popped value is / is not zero (both edges are live)
    halt          stop
    L:            a label (a jump target); a bare `name:` line

The reader is deliberately small and total: an unknown mnemonic is a loud error (DeadCodeError),
never skipped. Nothing here executes a challenge: the text is parsed into blocks and walked as a
graph.

API:

  parse(src) -> Program
      Blocks, edges and labels of the source. DeadCodeError on an unknown op or an undefined label.

  Program.reachable() -> set[int]        block ids reachable from the entry (block 0), forward only
  Program.dead_blocks() -> [Block]       blocks no execution path can enter, in source order
  Program.dead_constants() -> [int]      every value pushed in a dead block, in source order
  Program.dead_output() -> bytes         the bytes a dead block's emit/emitn sequence would print
                                         (push then emit/emitn), i.e. the hidden string, in order

  extract(src) -> bytes                  convenience: parse(src).dead_output()
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field


class DeadCodeError(ValueError):
    """The program text is malformed: an unknown mnemonic, a bad operand, or an undefined label."""


_BRANCH = {"jmp", "jz", "jnz"}
_UNARY_INT = {"push"}
_NO_ARG = {"emit", "emitn", "dup", "add", "sub", "mul", "pop", "halt", "swap"}


@dataclass
class Instr:
    op: str
    arg: object = None
    line: int = 0


@dataclass
class Block:
    id: int
    instrs: list = field(default_factory=list)
    succ: set = field(default_factory=set)      # successor block ids (fallthrough and branch targets)
    label: str | None = None


@dataclass
class Program:
    blocks: list
    entry: int = 0

    def reachable(self) -> set:
        seen = set()
        if not self.blocks:
            return seen
        stack = [self.entry]
        while stack:
            b = stack.pop()
            if b in seen:
                continue
            seen.add(b)
            stack.extend(self.blocks[b].succ - seen)
        return seen

    def dead_blocks(self) -> list:
        live = self.reachable()
        return [b for b in self.blocks if b.id not in live]

    def dead_constants(self) -> list:
        vals = []
        for b in self.dead_blocks():
            for ins in b.instrs:
                if ins.op == "push":
                    vals.append(ins.arg)
        return vals

    def dead_output(self) -> bytes:
        """The bytes dead code would print: walk each dead block in order with a local stack, applying
        push and emit/emitn (and dup/pop so a `push; dup; emit; emit` doubles). Arithmetic on dead
        stacks is honoured when both operands are known, else the result is dropped (unknown)."""
        out = bytearray()
        for b in self.dead_blocks():
            st: list = []
            for ins in b.instrs:
                if ins.op == "push":
                    st.append(ins.arg)
                elif ins.op == "dup":
                    if st:
                        st.append(st[-1])
                elif ins.op == "pop":
                    if st:
                        st.pop()
                elif ins.op == "swap":
                    if len(st) >= 2:
                        st[-1], st[-2] = st[-2], st[-1]
                elif ins.op in ("add", "sub", "mul"):
                    if len(st) >= 2:
                        a = st.pop()
                        c = st.pop()
                        st.append(c + a if ins.op == "add" else c - a if ins.op == "sub" else c * a)
                elif ins.op == "emit":
                    if st:
                        out.append(st.pop() & 0xFF)
                elif ins.op == "emitn":
                    if st:
                        out += str(st.pop()).encode("ascii")
                # branches / halt inside a block end nothing here; blocks are already split on them
        return bytes(out)


_LABEL_RE = re.compile(r"^([A-Za-z_.$][\w.$]*):$")


def _tokenise(src: str):
    """[(op, arg, lineno)] | label markers ('label', name, lineno). Comments start with ; or #."""
    items = []
    for lineno, raw in enumerate(src.splitlines(), 1):
        line = raw.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        m = _LABEL_RE.match(line)
        if m:
            items.append(("label", m.group(1), lineno))
            continue
        parts = line.split()
        op = parts[0].lower()
        if op in _BRANCH:
            if len(parts) != 2:
                raise DeadCodeError(f"line {lineno}: {op} needs one label")
            items.append((op, parts[1], lineno))
        elif op in _UNARY_INT:
            if len(parts) != 2:
                raise DeadCodeError(f"line {lineno}: {op} needs one integer")
            try:
                items.append((op, int(parts[1], 0), lineno))
            except ValueError:
                raise DeadCodeError(f"line {lineno}: {op} operand {parts[1]!r} is not an integer")
        elif op in _NO_ARG:
            if len(parts) != 1:
                raise DeadCodeError(f"line {lineno}: {op} takes no operand")
            items.append((op, None, lineno))
        else:
            raise DeadCodeError(f"line {lineno}: unknown mnemonic {op!r}")
    return items


def parse(src: str) -> Program:
    """Parse the bytecode into a Program (blocks + CFG). A new block starts at the entry, at any label,
    and after any jump/halt; edges follow fallthrough (except after jmp/halt) and branch targets."""
    items = _tokenise(src)
    # First pass: cut into blocks. A block boundary is forced before a label and after a terminator.
    blocks: list = []
    labels: dict = {}

    def new_block(label=None):
        b = Block(id=len(blocks), label=label)
        blocks.append(b)
        if label is not None:
            labels[label] = b.id
        return b

    cur = new_block()
    start_fresh = True          # the current block is empty / just started
    for op, arg, lineno in items:
        if op == "label":
            # A label always starts a block so it can be a jump target; chain fallthrough.
            if start_fresh and not cur.instrs and cur.label is None:
                cur.label = arg
                labels[arg] = cur.id
            else:
                nxt = new_block(arg)
                if not _ends_block(cur):
                    cur.succ.add(nxt.id)        # provisional fallthrough, fixed in pass two
                cur = nxt
            start_fresh = True
            continue
        cur.instrs.append(Instr(op, arg, lineno))
        start_fresh = False
        if op in ("jmp", "jz", "jnz", "halt"):
            nxt = new_block()
            cur = nxt
            start_fresh = True

    # Drop a trailing empty block with no label.
    if blocks and not blocks[-1].instrs and blocks[-1].label is None and not blocks[-1].succ:
        if len(blocks) > 1:
            dead_id = blocks[-1].id
            for b in blocks:
                b.succ.discard(dead_id)
            blocks.pop()

    # Second pass: real edges from terminators / fallthrough.
    for i, b in enumerate(blocks):
        b.succ = set()
        term = b.instrs[-1] if b.instrs else None
        if term is None:
            if i + 1 < len(blocks):
                b.succ.add(i + 1)
            continue
        if term.op == "halt":
            continue
        if term.op == "jmp":
            b.succ.add(_target(labels, term))
            continue
        if term.op in ("jz", "jnz"):
            b.succ.add(_target(labels, term))
            if i + 1 < len(blocks):
                b.succ.add(i + 1)
            continue
        if i + 1 < len(blocks):
            b.succ.add(i + 1)                   # ordinary fallthrough
    return Program(blocks=blocks, entry=0)


def _ends_block(b: Block) -> bool:
    return bool(b.instrs) and b.instrs[-1].op in ("jmp", "jz", "jnz", "halt")


def _target(labels: dict, ins: Instr) -> int:
    if ins.arg not in labels:
        raise DeadCodeError(f"line {ins.line}: jump to undefined label {ins.arg!r}")
    return labels[ins.arg]


def extract(src: str) -> bytes:
    return parse(src).dead_output()


def _main(argv) -> int:       # pragma: no cover
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: deadcode.py <program.stackasm> ...", file=sys.stderr)
        return 0 if argv else 2
    for path in argv:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        try:
            prog = parse(src)
        except DeadCodeError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 2
        dead = prog.dead_output()
        print("%s: dead_blocks=%d dead_constants=%r dead_output=%r"
              % (path, len(prog.dead_blocks()), prog.dead_constants(), dead))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
