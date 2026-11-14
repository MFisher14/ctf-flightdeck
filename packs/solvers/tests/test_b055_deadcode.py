#!/usr/bin/env python3
"""B-055: dead-code constant extractor (solvers/common/deadcode.py).

  .venv/bin/python -m pytest tests/test_b055_deadcode.py

Offline, no fixtures on disk: every program is a string built in the test. What is checked:

  reach      the entry block and everything a jump/fallthrough can reach is live; code after an
             unconditional jmp with no label, and code after halt, is dead.
  hidden     a flag pushed-and-emitted in a dead block is recovered by dead_output, in order, and is
             exactly what a real run would NOT print (the live path prints something else).
  both-edges jz / jnz keep BOTH targets live (a branch is never assumed taken or not), so a block only
             reachable through a branch is not called dead.
  arith      dead arithmetic (push push add emit) is evaluated when operands are known.
  loud       an unknown mnemonic, a bad operand and a jump to an undefined label each raise
             DeadCodeError (no silent skip).
  negative   a program with no dead code yields empty results (guards against always-finding-something).
"""
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import deadcode  # noqa: E402


def _flag_pushes(text):
    return "\n".join(f"push {b}\nemit" for b in text.encode())


def test_dead_block_after_jmp_is_hidden():
    # The live path prints "GO"; the flag is assembled only after an unconditional jump, never run.
    src = f"""
        push {ord('G')}
        emit
        push {ord('O')}
        emit
        jmp done
        ; ---- dead: reachable from nowhere ----
        {_flag_pushes('flag{d34d}')}
      done:
        halt
    """
    prog = deadcode.parse(src)
    assert prog.dead_output() == b"flag{d34d}"
    # Sanity: the dead constants are the byte values of the hidden flag, in order.
    assert bytes(prog.dead_constants()) == b"flag{d34d}"
    # The live blocks really do reach `done`; the dead block's id is not among the reachable set.
    live = prog.reachable()
    dead_ids = {b.id for b in prog.dead_blocks()}
    assert dead_ids and not (dead_ids & live)


def test_code_after_halt_is_dead():
    src = f"""
        push 65
        emit
        halt
        {_flag_pushes('SECRET')}
    """
    assert deadcode.extract(src) == b"SECRET"


def test_branch_keeps_both_edges_live():
    # A block reachable ONLY through the jz target must not be called dead.
    src = """
        push 0
        jz target
        push 88
        emit
      target:
        push 89
        emit
        halt
    """
    prog = deadcode.parse(src)
    assert prog.dead_output() == b""          # nothing is dead: both the fallthrough and target are live
    assert prog.dead_blocks() == []


def test_unreachable_only_via_label_jump_is_live():
    # `vault` is only reached by the jmp; it is live, so its constant is NOT reported as dead.
    src = """
        jmp vault
        push 1
        emit
      vault:
        push 90
        emit
        halt
    """
    prog = deadcode.parse(src)
    out = prog.dead_output()
    assert b"Z" not in out                     # the vault (push 90 -> 'Z') is live
    assert out == b"\x01"                       # only the orphaned `push 1; emit` block is dead


def test_dead_arithmetic_is_evaluated():
    src = """
        halt
        push 60
        push 5
        add
        emit
    """
    assert deadcode.extract(src) == bytes([65])


def test_emitn_in_dead_block():
    src = """
        halt
        push 1337
        emitn
    """
    assert deadcode.extract(src) == b"1337"


def test_no_dead_code_is_empty():
    src = """
        push 72
        emit
        halt
    """
    prog = deadcode.parse(src)
    assert prog.dead_blocks() == []
    assert prog.dead_output() == b""
    assert prog.dead_constants() == []


@pytest.mark.parametrize("src, needle", [
    ("push 1\nfrobnicate", "unknown mnemonic"),
    ("push notanint", "not an integer"),
    ("jmp nowhere\nhalt", "undefined label"),
    ("push", "needs one integer"),
    ("emit 3", "takes no operand"),
])
def test_malformed_is_loud(src, needle):
    with pytest.raises(deadcode.DeadCodeError) as ei:
        deadcode.parse(src)
    assert needle in str(ei.value)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
