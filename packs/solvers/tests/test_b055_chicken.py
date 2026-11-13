#!/usr/bin/env python3
"""B-055: Chicken esolang VM (solvers/common/chicken.py).

  .venv/bin/python -m pytest tests/test_b055_chicken.py

Offline, no fixtures on disk. Chicken has no public challenge in the four 2026 events, so there is no
real-data regression; these tests pin the documented opcode table (see the module docstring). Each
assertion follows necessarily from the opcode semantics, not from the implementation -- e.g. push 2,
push 3, add must leave 5 on the stack -- so a wrong interpreter fails them.

  parse      counting "chicken" per line gives the opcodes; a non-"chicken" token is a loud error;
             a single trailing newline does not add a phantom axe.
  arith      push (op-10), add, fox (subtract), rooster (multiply) and compare leave the spec result
             on the stack (checked via with_stack, independent of output rendering).
  strings    `chicken` pushes the literal string and add concatenates strings.
  pick       pick source 1 loads an input byte by index; pick source 0 loads a stack slot by index.
  halt/err   axe halts; a bad pick source and bad peck/fr/BBQ operands raise ChickenError (no silent
             fallback). Opcodes 7/8/9 (peck, fr, BBQ) were completed by B-250.
  output     a number on top renders as its code-point character (the documented convention).
"""
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import chicken  # noqa: E402

PUSH = lambda v: v + 10         # the opcode that pushes literal v


def test_count_opcodes():
    assert chicken.count_opcodes("chicken chicken\nchicken\n\n") == [2, 1, 0]
    # A single trailing newline is not a phantom axe (the real program keeps its last opcode).
    assert chicken.count_opcodes("chicken\n") == [1]
    with pytest.raises(chicken.ChickenError):
        chicken.count_opcodes("chicken duck")


def test_push_and_add():
    _, st = chicken.run([PUSH(2), PUSH(3), 2], with_stack=True)   # 2, 3, add
    assert st[-1] == 5


def test_subtract_and_multiply_order():
    # fox: b=pop, a=pop, push a-b. With push 10 then push 3: a=10, b=3 -> 7.
    _, st = chicken.run([PUSH(10), PUSH(3), 3], with_stack=True)
    assert st[-1] == 7
    _, st = chicken.run([PUSH(6), PUSH(7), 4], with_stack=True)   # rooster: 6*7
    assert st[-1] == 42


def test_compare():
    _, st = chicken.run([PUSH(5), PUSH(5), 5], with_stack=True)
    assert st[-1] == 1
    _, st = chicken.run([PUSH(5), PUSH(6), 5], with_stack=True)
    assert st[-1] == 0


def test_chicken_string_and_concat():
    _, st = chicken.run([1], with_stack=True)                     # chicken -> "chicken"
    assert st[-1] == "chicken"
    _, st = chicken.run([1, 1, 2], with_stack=True)               # "chicken" + "chicken"
    assert st[-1] == "chickenchicken"


def test_pick_from_input():
    # push index 2, pick source 1 -> the 3rd input byte.
    out, st = chicken.run([PUSH(2), 6, 1], stdin=b"ABCD", with_stack=True)
    assert st[-1] == ord("C")


def test_pick_from_stack():
    # Push three numbers; push index 2; pick source 0 -> stack[2] which is slot 2 == the first push.
    _, st = chicken.run([PUSH(9), PUSH(8), PUSH(7), PUSH(2), 6, 0], with_stack=True)
    assert st[-1] == 9          # stack = [prog, input, 9, 8, 7]; index 2 -> 9


def test_axe_halts_before_rest():
    # After axe (0), the push is never executed, so the top is the pre-axe value.
    _, st = chicken.run([PUSH(65), 0, PUSH(99)], with_stack=True)
    assert st[-1] == 65


def test_peck_fr_bbq_are_defined_b250():
    # B-250 completed the table (esolangs.org): 7 peck, 8 fr, 9 BBQ. Their semantics are in
    # tests/test_b250_warmups_residuals.py; here, the B-055 table no longer refuses them, and their
    # bad operands stay loud.
    _, st = chicken.run([PUSH(65), 9], with_stack=True)
    assert st[-1] == "&#65;"
    with pytest.raises(chicken.ChickenError):
        chicken.run([PUSH(5), PUSH(0), 7])      # peck into slot 0 (the program)
    with pytest.raises(chicken.ChickenError):
        chicken.run([PUSH(1), PUSH(0), PUSH(10), 3, 8])     # fr: cond 1, offset 0-10 = -10: before the start
    with pytest.raises(chicken.ChickenError):
        chicken.run([1, 9])                     # BBQ of a string


def test_bad_pick_source_is_loud():
    with pytest.raises(chicken.ChickenError):
        chicken.run([PUSH(0), 6, 2])            # source 2 is undefined
    with pytest.raises(chicken.ChickenError):
        chicken.run([PUSH(0), 6])               # pick with no source operand


def test_output_renders_number_as_char():
    assert chicken.run([PUSH(65)]) == b"A"
    assert chicken.run([1]) == b"chicken"
    # Build 'Hi': push 'H'(72) then 'i'(105) as chars and concatenate via the chicken string? No --
    # render only touches the TOP, so a two-char output is one string. Concatenate char strings:
    # (chr via render) is per-value, so assemble the number then render. Here just check a round-trip
    # through source_of / run_source stays stable.
    assert chicken.run_source(chicken.source_of([PUSH(90)])) == b"Z"


def test_step_cap_is_loud():
    with pytest.raises(chicken.ChickenError):
        chicken.run([PUSH(1)], steps=0)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
