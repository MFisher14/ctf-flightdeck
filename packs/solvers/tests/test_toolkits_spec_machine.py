"""B-057: the spec-driven register machine (solvers/toolkits/spec_machine.py): the interpreter, the
spec and program validation, the framing readers, the conformance gate and the round handler.

Fixtures are synthetic (tests/spec_machine_fixtures.py). The service half and the CLI are in
tests/test_spec_machine_service.py.
"""
from __future__ import annotations

import json
import random
import tomllib

import pytest

import spec_machine as sm
from spec_machine_fixtures import TALLY, random_round, reference, round_text, tally


def machine(ops=None, **top):
    """A small 3-register machine (a, b, c) with `put` and `say`, plus the given ops and top-level keys."""
    data = {"registers": {"names": ["a", "b", "c"]},
            "ops": {"put": {"args": ["d:reg", "v:imm"], "do": "d = v"},
                    "say": {"args": ["x:val"], "do": "output(x)"}}}
    data["ops"].update(ops or {})
    data.update(top)
    return sm.parse_spec(data)


def text(spec, program, inputs=(), **kw):
    return sm.run(spec, program, inputs, **kw).text


THREE = ["d:reg", "x:reg", "y:reg"]


# ------------------------------------------------------------------------------------ the interpreter

def test_template_is_a_valid_spec_and_reproduces_its_own_examples():
    spec = sm.parse_spec(tomllib.loads(sm.TEMPLATE))
    report = sm.conformance(spec)
    assert (report.total, report.passed) == (3, 3) and report.ok
    assert [r.got for r in report.results] == ["54470", "65535 7 65535", "3 2 1 1"]


def test_differential_against_an_independent_reference_interpreter():
    spec = sm.parse_spec(TALLY)
    rng = random.Random(57)
    printed = 0
    for n in range(250):
        program, tape = random_round(rng)
        want = reference(program, tape)
        got = sm.run(spec, program, tape)
        assert got.text == want, f"program {n}:\n{program}\ntape {tape}"
        printed += len(got.outputs)
    assert printed > 600                      # the programs really print; an empty-vs-empty run proves nothing


@pytest.mark.parametrize("program, tape, want", [
    ("put r1 -5\nsay r1", [], "65531"),                                     # a negative immediate wraps
    ("put r1 70000\nsay r1", [], "4464"),
    ("get r1\nget r2\nadd r0 r1 r2\nsay r0", [65535, 2], "1"),
    ("put r1 3\nput r2 5\nsub r0 r1 r2\nsay r0", [], "65534"),
    ("put r1 300\nmul r0 r1 r1\nsay r0", [], "24464"),
    ("put r1 9\ndiv r0 r1 r2\nsay r0", [], "65535"),                         # x // 0
    ("put r1 9\nrem r0 r1 r2\nsay r0", [], "9"),                             # x % 0 is the dividend
    ("put r1 1\nput r2 17\nlsh r0 r1 r2\nsay r0", [], "2"),                  # count & 15
    ("put r1 32768\nput r2 16\nrsh r0 r1 r2\nsay r0", [], "32768"),          # 16 & 15 == 0
    ("put r1 32768\nput r2 15\nrsh r0 r1 r2\nsay r0", [], "1"),              # logical
    ("inv r0 r1\nsay r0", [], "65535"),
    ("get r1\nget r2\nsay r1\nsay r2", [7], "7 65535"),                      # a read past the tape
    ("put r1 5\nadd r1 r1 r1\nsay r1", [], "10"),                            # operands read before the write
])
def test_tally_quirks(program, tape, want):
    assert text(sm.parse_spec(TALLY), program, tape) == want


def test_word_width_is_configurable():
    add = {"add": {"args": THREE, "do": "d = x + y"}}
    prog = "put a 200\nput b 100\nadd c a b\nsay c"
    assert text(machine(add, word_bits=8), prog) == "44"
    assert text(machine(add, word_bits=16), prog) == "300"
    assert text(machine(add, word_bits=4), "put a 9\nput b 9\nadd c a b\nsay c") == "2"
    big = "put a 0xffffffff\nput b 2\nadd c a b\nsay c"
    assert text(machine(add, word_bits=32), big) == "1"
    assert text(machine(add, word_bits=64), big) == "4294967297"


def test_overflow_saturate_and_trap():
    ops = {"add": {"args": THREE, "do": "d = x + y"}, "sub": {"args": THREE, "do": "d = x - y"}}
    sat = machine(ops, word_bits=8, overflow="saturate")
    assert text(sat, "put a 200\nput b 100\nadd c a b\nsay c") == "255"
    assert text(sat, "put a 3\nput b 5\nsub c a b\nsay c") == "0"
    assert text(sat, "put a 3\nput b 5\nadd c a b\nsay c") == "8"
    trap = machine(ops, word_bits=8, overflow="trap")
    assert text(trap, "put a 250\nput b 5\nadd c a b\nsay c") == "255"
    with pytest.raises(sm.MachineTrap, match=r"line 3 `add c a b`: value 256 does not fit"):
        text(trap, "put a 250\nput b 6\nadd c a b\nsay c")
    with pytest.raises(sm.MachineTrap, match="value -1 does not fit"):
        text(trap, "put b 1\nsub c a b")


def test_signed_words():
    ops = {"add": {"args": THREE, "do": "d = x + y"}, "sub": {"args": THREE, "do": "d = x - y"},
           "asr": {"args": THREE, "do": "d = x >> y"}, "lsr": {"args": THREE, "do": "d = u(x) >> y"},
           "neg": {"args": ["x:reg", "t:label"], "do": "if x < 0: goto(t)"}}
    wrap = machine(ops, word_bits=8, signed=True)
    assert text(wrap, "put a 127\nput b 1\nadd c a b\nsay c") == "-128"
    assert text(wrap, "put a 200\nsay a") == "-56"
    assert text(wrap, "put a -8\nput b 1\nasr c a b\nsay c") == "-4"          # arithmetic on a signed word
    assert text(wrap, "put a -8\nput b 1\nlsr c a b\nsay c") == "124"         # u() makes it logical
    assert text(wrap, "put a -1\nneg a yes\nsay a\nyes: put b 7\nsay b") == "7"
    sat = machine(ops, word_bits=8, signed=True, overflow="saturate")
    assert text(sat, "put a 100\nput b 100\nadd c a b\nsay c") == "127"
    assert text(sat, "put a -100\nput b 100\nsub c a b\nsay c") == "-128"
    assert text(sat, "put a -1\nput b 1\nadd c a b\nsay c") == "0"            # -1 + 1 is not an overflow
    trap = machine(ops, word_bits=8, signed=True, overflow="trap")
    assert text(trap, "put a -128\nsay a") == "-128"
    with pytest.raises(sm.MachineTrap, match="value 128 does not fit a signed 8-bit"):
        text(trap, "put a 128")


def test_s_and_u_reinterpret_a_word():
    ops = {"sgn": {"args": ["d:reg", "x:reg"], "do": "d = 1 if s(x) < 0 else 0"},
           "uns": {"args": ["x:reg"], "do": "output(u(x) >> 4)"}}
    spec = machine(ops, word_bits=16)
    assert text(spec, "put a 32768\nsgn b a\nsay b\nput a 32767\nsgn b a\nsay b") == "1 0"
    assert text(machine(ops, word_bits=16, signed=True, io={"format": "dec"}), "put a -16\nuns a") == "4095"


def test_division_by_zero_rules():
    ops = {"div": {"args": THREE, "do": "d = x // y"}, "rem": {"args": THREE, "do": "d = x % y"}}
    prog = "put a 9\ndiv c a b\nsay c"
    with pytest.raises(sm.MachineTrap, match=r"line 2 `div c a b`: division by zero; set quirks.div_zero"):
        text(machine(ops), prog)
    with pytest.raises(sm.MachineTrap, match="remainder by zero; set quirks.mod_zero"):
        text(machine(ops), "put a 9\nrem c a b")
    assert text(machine(ops, quirks={"div_zero": 0}), prog) == "0"
    assert text(machine(ops, quirks={"div_zero": 77}), prog) == "77"
    assert text(machine(ops, quirks={"div_zero": "dividend"}), prog) == "9"
    assert text(machine(ops, quirks={"mod_zero": 5}), "put a 9\nrem c a b\nsay c") == "5"
    assert text(machine(ops, quirks={"mod_zero": "dividend"}), "put a 9\nrem c a b\nsay c") == "9"
    # the rules are separate: a div_zero rule does not make % 0 legal
    with pytest.raises(sm.MachineTrap, match="remainder by zero"):
        text(machine(ops, quirks={"div_zero": 0}), "put a 9\nrem c a b")
    assert text(machine(ops), "put a 9\nput b 2\ndiv c a b\nsay c\nrem c a b\nsay c") == "4 1"


def test_floor_and_truncating_division_differ_on_signed_words():
    ops = {"fdiv": {"args": THREE, "do": "d = x // y"}, "frem": {"args": THREE, "do": "d = x % y"},
           "tdiv": {"args": THREE, "do": "d = tdiv(x, y)"}, "trem": {"args": THREE, "do": "d = tmod(x, y)"}}
    spec = machine(ops, signed=True, quirks={"div_zero": -1, "mod_zero": "dividend"})
    lead = "put a -7\nput b 2\n"
    assert text(spec, lead + "fdiv c a b\nsay c\nfrem c a b\nsay c") == "-4 1"
    assert text(spec, lead + "tdiv c a b\nsay c\ntrem c a b\nsay c") == "-3 -1"
    assert text(spec, "put a 7\nput b -2\ntdiv c a b\nsay c\ntrem c a b\nsay c") == "-3 1"
    assert text(spec, "put a -7\nput b -2\ntdiv c a b\nsay c") == "3"
    assert text(spec, "put a -7\nput b 0\ntdiv c a b\nsay c\ntrem c a b\nsay c") == "-1 -7"   # the quirks apply


def test_shift_rules():
    ops = {"shl": {"args": THREE, "do": "d = x << y"}, "shr": {"args": THREE, "do": "d = x >> y"}}
    plain = machine(ops)
    assert text(plain, "put a 1\nput b 15\nshl c a b\nsay c") == "32768"
    assert text(plain, "put a 1\nput b 16\nshl c a b\nsay c") == "0"           # shifted out, no mask
    assert text(plain, "put a 1\nput b 60000\nshl c a b\nsay c") == "0"        # a huge count is still just 0
    assert text(plain, "put a 40000\nput b 16\nshr c a b\nsay c") == "0"
    masked = machine(ops, quirks={"shift_mask": 15})
    assert text(masked, "put a 1\nput b 16\nshl c a b\nsay c") == "1"
    assert text(masked, "put a 40000\nput b 17\nshr c a b\nsay c") == "20000"
    assert text(machine(ops, quirks={"shift_mask": 7}), "put a 1\nput b 9\nshl c a b\nsay c") == "2"
    signed = machine(ops, signed=True)
    with pytest.raises(sm.MachineTrap, match="shift by a negative count"):
        text(signed, "put a 1\nput b -1\nshl c a b")
    sat = machine(ops, overflow="saturate")
    assert text(sat, "put a 1\nput b 60000\nshl c a b\nsay c") == "65535"


def test_bitwise_unary_and_boolean_operators():
    ops = {"t": {"args": THREE, "do": "d = (x & y) | (x ^ y)"},
           "n": {"args": ["d:reg", "x:reg"], "do": "d = -x"},
           "inv": {"args": ["d:reg", "x:reg"], "do": "d = ~x"},
           "lnot": {"args": ["d:reg", "x:reg"], "do": "d = not x"},
           "both": {"args": THREE, "do": "d = x and y"},
           "any": {"args": THREE, "do": "d = x or y"},
           "btw": {"args": THREE, "do": "d = 1 if x < d <= y else 0"},
           "ne": {"args": THREE, "do": "d = (x != y) + (x >= y) * 2 + (x > y) * 4 + (x == y) * 8"}}
    spec = machine(ops)
    assert text(spec, "put a 12\nput b 10\nt c a b\nsay c") == "14"
    assert text(spec, "put a 1\nn c a\nsay c\ninv c a\nsay c") == "65535 65534"
    assert text(spec, "put a 5\nlnot c a\nsay c\nlnot c b\nsay c") == "0 1"
    assert text(spec, "put a 5\nboth c a b\nsay c\nany c a b\nsay c\nput b 9\nboth c a b\nsay c") == "0 1 1"
    assert text(spec, "any c a b\nsay c") == "0"
    assert text(spec, "put a 2\nput b 5\nput c 5\nbtw c a b\nsay c\nput c 2\nbtw c a b\nsay c\n"
                      "put c 6\nbtw c a b\nsay c") == "1 0 0"
    assert text(spec, "put a 3\nput b 3\nne c a b\nsay c\nput a 4\nne c a b\nsay c\nput a 2\nne c a b\nsay c") \
        == "10 7 1"


def test_flags_update_only_on_the_instructions_that_list_them():
    flags = {"zf": {"update": "result == 0"}, "cf": {"update": "raw > mask or raw < 0"}}
    ops = {"add": {"args": THREE, "do": "d = x + y", "sets": ["zf", "cf"]},
           "sub": {"args": THREE, "do": "d = x - y", "sets": ["zf", "cf"]},
           "inc": {"args": ["d:reg"], "do": "d = d + 1", "sets": ["zf"]},     # the quirk: inc leaves carry alone
           "mov": {"args": ["d:reg", "x:reg"], "do": "d = x"},               # and mov touches no flag
           "adc": {"args": THREE, "do": "d = x + y + cf", "sets": ["zf", "cf"]},
           "cmp": {"args": ["x:reg", "y:reg"], "do": "_ = x - y", "sets": ["zf", "cf"]},
           "stc": {"do": "cf = 5"},
           "fl": {"do": "output(zf); output(cf)"}}
    spec = machine(ops, flags=flags)
    assert text(spec, "put a 65535\nput b 1\nadd c a b\nfl") == "1 1"          # wrapped to zero, carried
    assert text(spec, "put a 2\nput b 1\nadd c a b\nfl") == "0 0"
    assert text(spec, "put a 1\nput b 2\nsub c a b\nfl") == "0 1"              # a borrow
    assert text(spec, "put a 65535\nput b 1\nadd c a b\nmov c a\nfl") == "1 1"   # mov kept both
    assert text(spec, "put a 65535\nput b 1\nadd c a b\ninc a\nfl") == "1 1"    # inc: z from 0, carry kept
    assert text(spec, "put a 65535\nput b 1\nadd c a b\ninc b\nfl") == "0 1"
    assert text(spec, "put a 65535\nput b 1\nadd c a b\nput a 0\nput b 0\nadc c a b\nsay c\nfl") == "1 0 0"
    assert text(spec, "put a 4\nput b 4\ncmp a b\nfl\nsay a") == "1 0 4"       # cmp writes no register
    assert text(spec, "stc\nfl") == "0 1"                                    # a flag holds 0 or 1
    result = sm.run(spec, "put a 65535\nput b 1\nadd c a b")
    assert result.flags == {"zf": 1, "cf": 1} and result.registers == {"a": 65535, "b": 1, "c": 0}


def test_flag_formulas_see_the_flags_from_before_the_instruction_and_initial_values():
    flags = {"z": {"update": "result == 0"}, "w": {"update": "z"}, "k": {"init": 1}}
    ops = {"tst": {"args": ["x:reg"], "do": "_ = x", "sets": ["z", "w"]},
           "fl": {"do": "output(z); output(w); output(k)"}}
    spec = machine(ops, flags=flags)
    assert text(spec, "fl") == "0 0 1"
    assert text(spec, "tst a\nfl") == "1 0 1"             # w copied the old z (0), not the new one
    assert text(spec, "tst a\ntst a\nfl") == "1 1 1"


def test_a_local_assignment_sets_raw_and_result_for_the_flag_formulas():
    flags = {"zf": {"update": "result == 0"}, "cf": {"update": "raw < 0"}, "nf": {"update": "result > 32767"}}
    ops = {"cmp": {"args": ["x:reg", "y:reg"], "do": "_ = x - y", "sets": ["zf", "cf", "nf"]},
           "fl": {"do": "output(zf); output(cf); output(nf)"}}
    spec = machine(ops, flags=flags)
    # 1 - 2: raw is -1 (a borrow), result is the wrapped word 65535 (negative), and neither register changed
    assert text(spec, "put a 1\nput b 2\ncmp a b\nfl\nsay a\nsay b") == "0 1 1 1 2"
    assert text(spec, "put a 2\nput b 1\ncmp a b\nfl") == "0 0 0"
    assert text(spec, "put a 2\nput b 2\ncmp a b\nfl") == "1 0 0"


def test_call_depth_is_capped_exactly(monkeypatch):
    monkeypatch.setattr(sm, "MAX_CALL_DEPTH", 3)
    ops = {"cal": {"args": ["t:label"], "do": "call(t)"}, "ret": {"do": "ret()"}, "hlt": {"do": "halt()"}}
    spec = machine(ops)
    three = "cal one\nhlt\none: cal two\nret\ntwo: cal three\nret\nthree: say 3\nret"
    assert text(spec, three) == "3"
    four = three.replace("three: say 3", "three: cal four") + "\nfour: say 4\nret"
    with pytest.raises(sm.MachineTrap, match=r"line 7 `three: cal four`: call depth over 3"):
        text(spec, four)


def test_labels_and_jumps():
    flags = {"z": {"update": "result == 0"}}
    ops = {"dec": {"args": ["d:reg"], "do": "d = d - 1", "sets": ["z"]},
           "jnz": {"args": ["t:label"], "do": "if not z: goto(t)"},
           "jmp": {"args": ["t:label"], "do": "goto(t)"},
           "jix": {"args": ["n:imm"], "do": "goto(n)"}}
    spec = machine(ops, flags=flags)
    assert text(spec, "put a 3\nloop: say a\ndec a\njnz loop\nsay b") == "3 2 1 0"
    assert text(spec, "put a 3\nloop:\n  say a\n  dec a\n  jnz loop") == "3 2 1"      # a label on its own line
    assert text(spec, "jmp skip\nsay 1\nskip: say 2") == "2"
    assert text(spec, "say 1\njmp fin\nsay 2\nfin:") == "1"                           # a label after the last line
    assert text(spec, "jix 2\nsay 1\nsay 2") == "2"                                   # an index: 0-based
    assert text(spec, "say 1\njix 3\nsay 2") == "1"                                   # the end is a target
    with pytest.raises(sm.MachineTrap, match=r"line 1 `jix 4`: jump to instruction 4, outside the program \(0..3\)"):
        text(spec, "jix 4\nsay 1\nsay 2")
    with pytest.raises(sm.MachineTrap, match="jump to instruction -1"):
        text(spec, "jix -1")
    with pytest.raises(sm.ProgramError, match=r"line 1 `jmp nowhere`: unknown label 'nowhere'"):
        sm.parse_program(spec, "jmp nowhere")
    with pytest.raises(sm.ProgramError, match=r"line 2 `x: say 2`: label 'x' is defined twice"):
        sm.parse_program(spec, "x: say 1\nx: say 2")
    assert sm.parse_program(spec, "say 1\nmid: say 2\nfin:").labels == {"mid": 1, "fin": 2}


BLOCKS = {"times": {"kind": "repeat", "args": ["n:val"], "count": "n"},
          "ifz": {"kind": "if", "args": ["x:reg"], "cond": "x == 0"},
          "while": {"kind": "while", "args": ["x:reg"], "cond": "x != 0"}}
BLOCK_OPS = {"dec": {"args": ["d:reg"], "do": "d = d - 1"}, "inc": {"args": ["d:reg"], "do": "d = d + 1"},
             "jmp": {"args": ["t:label"], "do": "goto(t)"}}


def test_structured_blocks():
    spec = machine(BLOCK_OPS, blocks=BLOCKS)
    assert text(spec, "times 3\n inc a\nend\nsay a") == "3"
    assert text(spec, "times 0\n inc a\nend\nsay a") == "0"
    assert text(spec, "times -2\n inc a\nend\nsay a") == "0"
    assert text(spec, "times 3\n times 4\n  inc a\n end\n inc b\nend\nsay a\nsay b") == "12 3"
    # the count is read once, at entry: changing the register inside does not change the trips
    assert text(spec, "put b 3\ntimes b\n inc a\n put b 100\nend\nsay a") == "3"
    assert text(spec, "ifz a\n say 1\nend\nsay 2") == "1 2"
    assert text(spec, "put a 5\nifz a\n say 1\nend\nsay 2") == "2"
    assert text(spec, "ifz a\n say 1\nelse\n say 2\nend\nsay 3") == "1 3"
    assert text(spec, "put a 5\nifz a\n say 1\nelse\n say 2\nend\nsay 3") == "2 3"
    # an `if` is tested once: making the condition false inside does not cut the body short
    assert text(spec, "ifz a\n inc a\n say a\nend") == "1"
    # a `while` is tested again after every trip
    assert text(spec, "put a 3\nwhile a\n say a\n dec a\nend\nsay 9") == "3 2 1 9"
    assert text(spec, "while a\n say 1\nend\nsay 9") == "9"
    assert text(spec, "put a 2\nwhile a\n ifz b\n  say 7\n else\n  say 8\n end\n inc b\n dec a\nend") == "7 8"


def test_step_count_is_exact():
    spec = machine(BLOCK_OPS, blocks=BLOCKS)
    assert sm.run(spec, "put a 1\nsay a\nsay a").steps == 3
    assert sm.run(spec, "times 2\n inc a\nend").steps == 5            # open, then (body, end) twice
    assert sm.run(spec, "times 0\n inc a\nend").steps == 1
    assert sm.run(spec, "ifz a\n inc a\nelse\n inc b\nend").steps == 3            # if, body, else (which leaves)
    assert sm.run(spec, "put a 1\nifz a\n inc a\nelse\n inc b\nend").steps == 4   # put, if, the else body, end
    assert sm.run(spec, "put a 2\nwhile a\n dec a\nend").steps == 6


def test_jumps_and_blocks_together():
    spec = machine(BLOCK_OPS, blocks=BLOCKS)
    # out of a block: its frame is dropped, the rest runs once
    assert text(spec, "put a 3\ntimes 5\n say a\n jmp out\nend\nout: say a") == "3 3"
    # out of two nested blocks, into the outer one: the outer loop keeps its count
    assert text(spec, "times 2\n times 9\n  say 1\n  jmp next\n end\n say 5\n next: say 2\nend\nsay 3") == "1 2 1 2 3"
    # inside one block
    assert text(spec, "times 2\n jmp over\n say 1\n over: say 2\nend") == "2 2"
    # back to the block's own opening line: it starts again, with a fresh count
    assert text(spec, "top: times 2\n say a\n inc a\n ifz b\n  inc b\n  jmp top\n end\nend") == "0 1 2"
    # `continue`: a jump to a label on the block's own `end` (or on the line just before it) stays in
    # the block, so the loop goes round again with its count or condition intact
    for cont in (" cont:\nend", "cont: end"):
        assert text(spec, f"times 3\n inc a\n jmp cont\n inc b\n{cont}\nsay a\nsay b") == "3 0"
        assert text(spec, f"put c 3\nwhile c\n dec c\n inc a\n jmp cont\n inc b\n{cont}\nsay a\nsay b") == "3 0"
        assert text(spec, f"times 2\n times 2\n  inc a\n  jmp cont\n  inc b\n {cont}\n inc c\nend\nsay a\nsay b\nsay c") == "4 0 2"
    with pytest.raises(sm.MachineTrap, match=r"line 1 `jmp inside`: jump into a block that is not running"):
        text(spec, "jmp inside\ntimes 2\n inside: say 1\nend")
    with pytest.raises(sm.MachineTrap, match="jump into a block that is not running"):
        text(spec, "times 2\n jmp other\nend\ntimes 2\n other: say 1\nend")


@pytest.mark.parametrize("program, why", [
    ("say 1\nend", r"line 2 `end`: `end` with no open block"),
    ("else", r"line 1 `else`: `else` with no open block"),
    ("times 2\nsay 1", r"line 1 `times 2`: block is never closed with `end`"),
    ("ifz a\n times 2\n say 1\nend", r"line 1 `ifz a`: block is never closed"),
    ("times 2\nelse\nend", r"line 2 `else`: `else` belongs to an `if` block, once"),
    ("ifz a\nelse\nelse\nend", r"line 3 `else`: `else` belongs to an `if` block, once"),
    ("times 2\nend 3", r"line 2 `end 3`: `end` takes no operand"),
    ("times\nend", r"line 1 `times`: times takes 1 operand\(s\) \(<n:val>\); got 0"),
])
def test_block_structure_errors(program, why):
    with pytest.raises(sm.ProgramError, match=why):
        sm.parse_program(machine(BLOCK_OPS, blocks=BLOCKS), program)


def test_end_and_else_words_are_configurable_and_free_without_blocks():
    spec = machine(BLOCK_OPS, blocks=BLOCKS, syntax={"end": "done", "else": "otherwise"})
    assert text(spec, "ifz a\n say 1\notherwise\n say 2\ndone") == "1"
    with pytest.raises(sm.ProgramError, match="unknown instruction 'end'"):
        sm.parse_program(spec, "ifz a\nend")
    plain = machine({"end": {"do": "halt()"}})                       # no blocks: `end` is an ordinary name
    assert text(plain, "say 1\nend\nsay 2") == "1"


def test_memory():
    ops = {"sto": {"args": ["i:val", "x:val"], "do": "mem[i] = x"},
           "lod": {"args": ["d:reg", "i:val"], "do": "d = mem[i]"},
           "bump": {"args": ["i:val"], "do": "mem[i] += 3"},
           "wide": {"args": ["i:val"], "do": "output(mem[i] > mask)"}}
    spec = machine(ops, memory={"size": 4})
    assert text(spec, "sto 0 7\nsto 3 70000\nlod a 0\nlod b 3\nlod c 1\nsay a\nsay b\nsay c") == "7 4464 0"
    assert text(spec, "sto 3 70000\nwide 3") == "0"                # a cell holds a word, not the value written
    assert text(spec, "sto 2 5\nbump 2\nbump 2\nlod a 2\nsay a") == "11"
    with pytest.raises(sm.MachineTrap, match=r"memory address 4 is outside 0..3; set quirks.mem_oob"):
        text(spec, "lod a 4")
    with pytest.raises(sm.MachineTrap, match="memory address -1 is outside"):
        text(spec, "sto -1 1")
    wrap = machine(ops, memory={"size": 4}, quirks={"mem_oob": "wrap"})
    assert text(wrap, "sto 5 9\nlod a 1\nsay a\nlod b -3\nsay b") == "9 9"
    with pytest.raises(sm.SpecError, match=r"ops.lod.do: uses mem\[...\] but the spec has no \[memory\] size"):
        machine({"lod": {"args": ["d:reg", "i:val"], "do": "d = mem[i]"}})


def test_stack_and_calls():
    ops = {"psh": {"args": ["x:val"], "do": "push(x)"}, "pop": {"args": ["d:reg"], "do": "d = pop()"},
           "cal": {"args": ["t:label"], "do": "call(t)"}, "ret": {"do": "ret()"}, "hlt": {"do": "halt()"},
           "inc": {"args": ["d:reg"], "do": "d = d + 1"}, "wide": {"do": "output(pop() > mask)"}}
    spec = machine(ops, stack={"size": 3}, blocks=BLOCKS)
    assert text(spec, "psh 1\npsh 2\npsh 70000\npop a\npop b\npop c\nsay a\nsay b\nsay c") == "4464 2 1"
    assert text(spec, "psh 70000\nwide") == "0"                     # the stack holds words
    with pytest.raises(sm.MachineTrap, match=r"line 4 `psh 4`: stack overflow: more than stack.size = 3 words"):
        text(spec, "psh 1\npsh 2\npsh 3\npsh 4")
    with pytest.raises(sm.MachineTrap, match="pop from an empty stack; set quirks.pop_empty"):
        text(spec, "pop a")
    assert text(machine(ops, stack={"size": 3}, quirks={"pop_empty": 42}), "pop a\nsay a") == "42"
    # a subroutine, called twice, returns to the line after each call
    assert text(spec, "cal sub\nsay 1\ncal sub\nsay 2\nhlt\nsub: inc a\nsay a\nret") == "1 1 2 2"
    # a call from inside a loop comes back into the loop with its count intact
    assert text(spec, "times 3\n cal sub\n say 0\nend\nhlt\nsub: inc a\nsay a\nret") == "1 0 2 0 3 0"
    with pytest.raises(sm.MachineTrap, match="ret with no call to return to"):
        text(spec, "ret")
    with pytest.raises(sm.MachineTrap, match=f"call depth over {sm.MAX_CALL_DEPTH}"):
        text(spec, "again: cal again")
    with pytest.raises(sm.SpecError, match=r"ops.psh.do: uses push\(\) but the spec has no \[stack\] size"):
        machine({"psh": {"args": ["x:val"], "do": "push(x)"}})


def test_halt_stops_the_run_and_is_reported():
    spec = machine({"hlt": {"do": "halt()"}})
    stopped = sm.run(spec, "say 1\nhlt\nsay 2")
    assert (stopped.text, stopped.halted, stopped.steps) == ("1", True, 2)
    assert sm.run(spec, "say 1").halted is False


def test_fuel_caps_executed_instructions():
    spec = machine(BLOCK_OPS, blocks=BLOCKS, limits={"fuel": 50})
    forever = "put a 1\nwhile a\n inc b\nend"
    with pytest.raises(sm.FuelExhausted, match="fuel exhausted: 50 instructions executed"):
        sm.run(spec, forever)                                         # the spec's own limit
    with pytest.raises(sm.FuelExhausted, match=r"fuel exhausted: 7 instructions executed, stopped at line 4 `end`"):
        sm.run(spec, forever, fuel=7)                                 # an explicit budget wins
    assert issubclass(sm.FuelExhausted, sm.MachineTrap)
    done = "times 2\n inc a\nend"                                     # exactly 5 instructions
    assert sm.run(spec, done, fuel=5).registers["a"] == 2
    with pytest.raises(sm.FuelExhausted):
        sm.run(spec, done, fuel=4)
    with pytest.raises(sm.FuelExhausted, match="line 1 `l: jmp l`"):
        sm.run(spec, "l: jmp l", fuel=1000)
    assert sm.parse_spec(TALLY).fuel == sm.DEFAULT_FUEL == 1_000_000


def test_output_formats():
    prog = "say 65\nsay 0\nsay 65535\nsay 300"
    assert text(machine(), prog) == "65 0 65535 300"
    assert text(machine(io={"format": "signed"}), prog) == "65 0 -1 300"
    assert text(machine(io={"format": "hex"}), prog) == "41 0 ffff 12c"
    assert text(machine(io={"format": "hex", "width": 4, "prefix": "0x", "separator": ","}), prog) \
        == "0x0041,0x0000,0xffff,0x012c"
    assert text(machine(io={"format": "dec", "width": 3, "separator": "\n"}), "say 7\nsay 1234") == "007\n1234"
    assert text(machine(io={"format": "char"}), "say 72\nsay 105") == "Hi"
    assert text(machine(io={"format": "char", "separator": "-"}), "say 72\nsay 105") == "H-i"
    assert text(machine(), "put a 1") == ""
    assert text(machine(io={"empty": "(none)"}), "put a 1") == "(none)"
    assert sm.run(machine(), prog).outputs == (65, 0, 65535, 300)
    assert text(machine(), "say 70000") == "4464"                    # an output is a word too
    with pytest.raises(sm.MachineTrap, match="more than limits.max_output = 2 output words"):
        text(machine(limits={"max_output": 2}), "say 1\nsay 2\nsay 3")


def test_input_tape():
    ops = {"get": {"args": ["d:reg"], "do": "d = input()"}, "skip": {"do": "input()"}}
    assert text(machine(ops), "get a\nskip\nget b\nsay a\nsay b", [4, 5, 6]) == "4 6"
    with pytest.raises(sm.MachineTrap, match=r"line 2 `get b`: input read past the end of the tape; set quirks.input_eof"):
        text(machine(ops), "get a\nget b", [4])
    assert text(machine(ops, quirks={"input_eof": 0}), "get a\nget b\nsay a\nsay b", [4]) == "4 0"
    assert text(machine(ops, quirks={"input_eof": 65535}), "get b\nsay b") == "65535"


def test_locals_raw_and_result():
    ops = {"mulw": {"args": ["hi:reg", "lo:reg", "x:reg", "y:reg"], "do": "_p = x * y\nhi = _p >> 16\nlo = _p"},
           "swap": {"args": ["x:reg", "y:reg"], "do": "_t = x; x = y; y = _t"},
           "probe": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x + y; output(raw >> 16); output(result)"}}
    spec = machine(ops)
    assert text(spec, "put a 300\nput b 300\nmulw c a a b\nsay c\nsay a") == "1 24464"    # 90000 = 1 * 65536 + 24464
    assert text(spec, "put a 1\nput b 2\nswap a b\nsay a\nsay b") == "2 1"
    # raw is the value before it was fitted (70000), result the stored word (4464)
    assert sm.run(spec, "put a 65535\nput b 4465\nprobe c a b").outputs == (1, 4464)
    wide = machine({"probe": {"args": ["d:reg", "x:reg"], "do": "d = x + 1; d = 1 if raw > mask else 0"}})
    assert text(wide, "put a 65535\nprobe b a\nsay b") == "1"
    assert text(wide, "put a 65534\nprobe b a\nsay b") == "0"
    with pytest.raises(sm.SpecError, match=r"ops.bad.do: unknown name '_never'"):
        machine({"bad": {"args": ["d:reg"], "do": "d = _never"}})


def test_named_registers_constants_and_initial_values():
    ops = {"acc": {"args": ["x:val"], "do": "a = a + x"},           # an implicit register, named in `do`
           "top": {"args": ["d:reg"], "do": "d = mask - bits"}}
    spec = machine(ops, registers={"names": ["a", "b", "c"], "init": {"b": 7, "c": -1}})
    assert text(spec, "acc 5\nacc b\nsay a\nsay c") == "12 65535"
    assert text(spec, "top a\nsay a") == "65519"                    # 65535 - 16
    assert sm.run(spec, "say 1").registers == {"a": 0, "b": 7, "c": 65535}
    counted = sm.parse_spec({"registers": {"count": 3, "prefix": "x"}, "ops": {"o": {"args": ["r:reg"], "do": "output(r)"}}})
    assert counted.registers == ("x0", "x1", "x2")
    with pytest.raises(sm.ProgramError, match="'x3' is not a register"):
        sm.parse_program(counted, "o x3")


def test_trace_reports_every_executed_line_with_the_state_after_it():
    spec = machine({"inc": {"args": ["d:reg"], "do": "d = d + 1", "sets": ["z"]}}, blocks=BLOCKS,
                   flags={"z": {"update": "result == 0"}})
    seen = []
    sm.run(spec, "put a 65535\ntimes 2\n  inc a\nend", trace=lambda *row: seen.append(row))
    assert [(line, src) for line, src, _, _ in seen] == [
        (1, "put a 65535"), (2, "times 2"), (3, "inc a"), (4, "end"), (3, "inc a"), (4, "end")]
    assert seen[2][2] == {"a": 0, "b": 0, "c": 0} and seen[2][3] == {"z": 1}
    assert seen[4][2]["a"] == 1 and seen[4][3] == {"z": 0}


# --------------------------------------------------------------------------------------------- programs

def test_program_syntax():
    ops = {"add": {"args": THREE, "do": "d = x + y"}}
    spec = machine(ops)
    assert text(spec, "put a, 0x10 ; sixteen\nput b,0b11   # three\n\n   \nadd c, a, b\nsay c\nsay 0o17\nsay +4") == "19 15 4"
    assert text(spec, "say 7 ; the first leader on the line wins # not this one") == "7"
    assert text(spec, "say 8 # and the other way round ; too") == "8"
    slash = machine(ops, syntax={"comment": ["//"], "separators": ",()"})
    assert text(slash, "put(a, 5) // five\nsay(a)") == "5"
    with pytest.raises(sm.ProgramError, match="unknown instruction '#'"):
        sm.parse_program(slash, "# not a comment here")
    dollar = machine(ops, syntax={"imm_prefix": "$"})
    assert text(dollar, "put a $7\nsay a\nsay $0x1f\nsay 3") == "7 31 3"
    with pytest.raises(sm.ProgramError, match=r"operand 'v': '\$\$7' is not an integer"):
        sm.parse_program(dollar, "put a $$7")
    upper = machine(ops, syntax={"case_sensitive": False})
    assert text(upper, "PUT A 5\nSay a\nsay 0X1F") == "5 31"
    with pytest.raises(sm.ProgramError, match="unknown instruction 'PUT'"):
        sm.parse_program(spec, "PUT a 5")


@pytest.mark.parametrize("program, why", [
    ("put a 1\nnope a", r"line 2 `nope a`: unknown instruction 'nope'"),
    ("put a", r"line 1 `put a`: put takes 2 operand\(s\) \(<d:reg> <v:imm>\); got 1"),
    ("put a 1 2", r"put takes 2 operand\(s\).*got 3"),
    ("put z 1", r"line 1 `put z 1`: operand 'd': 'z' is not a register"),
    ("put 5 1", r"operand 'd': '5' is not a register"),
    ("put a b", r"operand 'v': 'b' is not an integer"),
    ("put a 1.5", r"operand 'v': '1.5' is not an integer"),
    ("put a 0x", r"'0x' is not an integer"),
    ("say q", r"operand 'x': 'q' is not a register or an integer"),
])
def test_program_errors_name_the_line(program, why):
    with pytest.raises(sm.ProgramError, match=why):
        sm.parse_program(machine(), program)


def test_program_size_limits():
    spec = machine()
    with pytest.raises(sm.ProgramError, match="a program is text"):
        sm.parse_program(spec, b"say 1")
    with pytest.raises(sm.ProgramError, match="more than 200000 instructions"):
        sm.parse_program(spec, "say 1\n" * (sm.MAX_PROGRAM_INSTRUCTIONS + 1))
    assert len(sm.parse_program(spec, "say 1\n" * 5)) == 5


# ------------------------------------------------------------------------------------------------ specs

@pytest.mark.parametrize("change, why", [
    ({"colour": "red"}, r"spec: unknown key\(s\) colour"),
    ({"word_bits": 0}, r"spec.word_bits: must be an integer 1..64; got 0"),
    ({"word_bits": 65}, r"spec.word_bits: must be an integer 1..64"),
    ({"word_bits": True}, r"spec.word_bits: must be an integer"),
    ({"overflow": "clip"}, r"spec.overflow: must be one of wrap, saturate, trap; got 'clip'"),
    ({"signed": 1}, r"spec.signed: must be true or false"),
    ({"registers": {}}, r"registers: needs names = \[...\] or count = N"),
    ({"registers": {"names": ["a", "a"]}}, r"registers.names: 'a' is named twice"),
    ({"registers": {"names": ["mem"]}}, r"registers.names: 'mem' is not a usable name"),
    ({"registers": {"names": ["1x"]}}, r"'1x' is not a usable name"),
    ({"registers": {"names": ["a"], "count": 2}}, r"registers: give names, or count \(\+ prefix\), not both"),
    ({"registers": {"count": 2, "init": {"r9": 1}}}, r"registers.init: unknown key\(s\) r9"),
    ({"registers": {"count": 2, "init": {"r1": "x"}}}, r"registers.init.r1: must be an integer"),
    ({"registers": {"count": 2, "colour": 1}}, r"registers: unknown key\(s\) colour"),
    ({"flags": {"r0": {}}}, r"flags: 'r0' is named twice"),
    ({"flags": {"z": {"init": 2}}}, r"flags.z.init: must be an integer 0..1"),
    ({"flags": {"z": {"update": "nope"}}}, r"flags.z.update: unknown name 'nope'"),
    ({"memory": {"size": 0}}, r"memory.size: must be an integer"),
    ({"stack": {"depth": 4}}, r"stack: unknown key\(s\) depth"),
    ({"quirks": {"div_zero": "explode"}}, r"quirks.div_zero: must be an integer or one of trap, dividend"),
    ({"quirks": {"input_eof": "dividend"}}, r"quirks.input_eof: must be an integer or one of trap"),
    ({"quirks": {"mem_oob": "clamp"}}, r"quirks.mem_oob: must be one of trap, wrap"),
    ({"quirks": {"shift_mask": -1}}, r"quirks.shift_mask: must be an integer"),
    ({"quirks": {"carry": 1}}, r"quirks: unknown key\(s\) carry"),
    ({"io": {"format": "octal"}}, r"io.format: must be one of dec, signed, hex, char"),
    ({"io": {"sep": ","}}, r"io: unknown key\(s\) sep"),
    ({"limits": {"fuel": 0}}, r"limits.fuel: must be an integer 1..1000000000"),
    ({"limits": {"fuel": 10 ** 10}}, r"limits.fuel: must be an integer"),
    ({"syntax": {"comment": "#"}}, r"syntax.comment: must be a list of non-empty strings"),
    ({"syntax": {"case": True}}, r"syntax: unknown key\(s\) case"),
    ({"ops": {}}, r"ops: the spec defines no instruction"),
    ({"ops": {"two words": {"do": "halt()"}}}, r"ops.two words: an instruction name is one word"),
    ({"ops": {"x": {"args": ["d:register"], "do": "halt()"}}}, r"ops.x.args\[0\]: kind must be one of reg, imm, val, label"),
    ({"ops": {"x": {"args": ["r0:reg"], "do": "halt()"}}}, r"ops.x.args\[0\]: operand name 'r0' is also a register"),
    ({"ops": {"x": {"args": ["d:reg", "d:reg"], "do": "halt()"}}}, r"ops.x.args\[1\]: operand name 'd' is also"),
    ({"ops": {"x": {"args": ["mask:reg"], "do": "halt()"}}}, r"operand name 'mask' is not usable"),
    ({"ops": {"x": {"args": "d:reg", "do": "halt()"}}}, r"ops.x.args: must be a list"),
    ({"ops": {"x": {"do": "halt()", "when": 1}}}, r"ops.x: unknown key\(s\) when"),
    ({"ops": {"x": {"args": ["d:reg"]}}}, r"ops.x.do: must be a non-empty string"),
    ({"ops": {"x": {"args": ["d:reg"], "do": "d = 1", "sets": ["z"]}}}, r"ops.x.sets: 'z' is not a flag with an `update`"),
    ({"flags": {"z": {"update": "result == 0"}}, "ops": {"x": {"do": "halt()", "sets": ["z"]}}},
     r"ops.x: sets flags but its `do` assigns no value"),
    ({"flags": {"z": {}}, "ops": {"x": {"args": ["d:reg"], "do": "d = 1", "sets": ["z"]}}}, r"'z' is not a flag with an `update`"),
    ({"blocks": {"loop": {"kind": "until", "cond": "1"}}}, r"blocks.loop.kind: must be one of repeat, if, while"),
    ({"blocks": {"loop": {"cond": "1"}}}, r"blocks.loop.kind: must be one of repeat, if, while"),
    ({"blocks": {"loop": {"kind": "repeat", "cond": "1"}}}, r"blocks.loop.cond: a repeat block takes `count`"),
    ({"blocks": {"loop": {"kind": "while", "count": "1"}}}, r"blocks.loop.count: a while block takes `cond`"),
    ({"blocks": {"loop": {"kind": "while"}}}, r"blocks.loop.cond: must be a non-empty string"),
    ({"blocks": {"end": {"kind": "while", "cond": "1"}}}, r"blocks.end: the name is already"),
    ({"blocks": {"o": {"kind": "while", "cond": "1"}}}, r"blocks.o: the name is already an instruction"),
    ({"blocks": {"w": {"kind": "while", "cond": "_x"}}}, r"blocks.w.cond: unknown name '_x'"),
    ({"examples": [{"program": "o r0"}]}, r"examples\[0\]: needs program and output"),
    ({"examples": [{"program": "o r0", "output": "0", "input": ["1"]}]}, r"examples\[0\].input: must be a list of integers"),
    ({"examples": [{"program": "o r0", "output": "0", "expect": "0"}]}, r"examples\[0\]: unknown key\(s\) expect"),
    ({"examples_files": ["e.txt"]}, r"examples_files: needs \[framing\]"),
    ({"framing": {"program_start": "P"}}, r"framing: needs program_start and program_end, or program_re"),
    ({"framing": {"program_re": "("}}, r"framing.program_re: not a regular expression"),
    ({"framing": {"program_re": "abc"}}, r"framing.program_re: needs one capture group"),
    ({"framing": {"program_re": "(a)", "program_start": "P"}}, r"framing: give program_re or program_start \+ program_end, not both"),
    ({"framing": {"program_re": "(a)", "input_prefix": "I", "input_re": "(i)"}}, r"framing: give input_prefix or input_re, not both"),
    ({"framing": {"program_re": "(a)", "prompt": ""}}, r"framing.prompt: must not be empty"),
    ({"framing": {"program_re": "(a)", "ask": ">"}}, r"framing: unknown key\(s\) ask"),
])
def test_spec_errors_name_the_key(change, why):
    data = {"registers": {"count": 2}, "ops": {"o": {"args": ["x:reg"], "do": "output(x)"}}}
    data.update(change)
    with pytest.raises(sm.SpecError, match=why):
        sm.parse_spec(data)


def test_case_insensitive_specs_need_lower_case_names():
    with pytest.raises(sm.SpecError, match="registers.names: 'A' must be lower-case"):
        sm.parse_spec({"syntax": {"case_sensitive": False}, "registers": {"names": ["A"]},
                       "ops": {"o": {"do": "halt()"}}})
    with pytest.raises(sm.SpecError, match="ops.Out: must be lower-case"):
        sm.parse_spec({"syntax": {"case_sensitive": False}, "registers": {"names": ["a"]},
                       "ops": {"Out": {"do": "halt()"}}})


@pytest.mark.parametrize("do, why", [
    ("import os", "Import is not a statement of the instruction language"),
    ("d = __import__('os')", "only these can be called"),
    ("d = x.real", "Attribute is not part of the instruction language"),
    ("d = x.__class__", "Attribute is not part of"),
    ("d = x / y", "`/` is not defined on words"),
    ("d = x ** y", "operator Pow is not part of"),
    ("d = x @ y", "operator MatMult is not part of"),
    ("d = [1][0]", r"only `mem\[...\]` can be indexed"),
    ("d = 'a'", "only integer constants are allowed"),
    ("d = 1.5", "only integer constants are allowed"),
    ("d = None", "only integer constants are allowed"),
    ("d = (lambda: 1)()", "only these can be called"),
    ("d = lambda: 1", "Lambda is not part of"),
    ("d = [1, 2]", "List is not part of"),
    ("d = (y := 1)", "NamedExpr is not part of"),
    ("d = x in (1, 2)", "comparison In is not part of"),
    ("d = x is y", "comparison Is is not part of"),
    ("nope = 1", "cannot assign to 'nope'"),
    ("d = nope", "unknown name 'nope'"),
    ("v = 1", "operand 'v' is imm: it cannot be assigned"),
    ("t = 1", "operand 't' is label: it cannot be assigned"),
    ("mask = 1", "'mask' is read-only"),
    ("raw = 1", "'raw' is read-only"),
    ("d = e = 1", "one target per assignment"),
    ("d, e = 1, 2", "an assignment target is a register"),
    ("output(x, y)", r"output\(\) takes 1 argument"),
    ("output()", r"output\(\) takes 1 argument"),
    ("output(x=1)", r"output\(\) takes 1 argument"),
    ("output(*x)", r"output\(\) takes 1 argument"),
    ("d = output(x)", r"output\(\) has no value"),
    ("d = goto(t)", r"goto\(\) has no value"),
    ("d = foo(x)", "only these can be called"),
    ("for i in x: pass", "For is not a statement"),
    ("while 1: pass", "While is not a statement"),
    ("x", "Expr is not a statement"),
    ("del d", "Delete is not a statement"),
    ("d = x if", "does not parse"),
    ("def f(): pass", "FunctionDef is not a statement"),
    ("d = " + "(" * 300 + "1" + ")" * 300, "does not parse|nested too deeply"),
    ("d = 1\n" * 700, r"too long \(more than 2000 syntax nodes\)"),
])
def test_the_do_language_refuses_everything_outside_it(do, why):
    data = {"registers": {"names": ["a", "e"]},
            "ops": {"t": {"args": ["d:reg", "x:reg", "y:reg", "v:imm", "t:label"], "do": do}}}
    with pytest.raises(sm.SpecError, match=why) as info:
        sm.parse_spec(data)
    assert str(info.value).startswith("ops.t.do: ")


def test_do_bodies_may_span_lines_and_branch():
    ops = {"clamp": {"args": ["d:reg", "x:val"], "do": """
                if x > 100:
                    d = 100
                elif x > 10:
                    d = 10
                else:
                    pass
                d += 1
            """},
           "wr": {"args": ["x:val"], "do": "x = 5"}}
    spec = machine(ops)
    assert text(spec, "clamp a 500\nsay a\nclamp b 50\nsay b\nclamp c 5\nsay c") == "101 11 1"
    assert text(spec, "wr a\nsay a") == "5"
    with pytest.raises(sm.MachineTrap, match=r"line 1 `wr 3`: operand 'x' is an immediate here: it cannot be written"):
        text(spec, "wr 3")


def test_load_spec_reads_toml_and_json_and_fails_loudly(tmp_path):
    toml = tmp_path / "t.machine.toml"
    toml.write_text(sm.TEMPLATE, encoding="utf-8")
    assert sm.load_spec(toml).name == "demo16" and sm.load_spec(toml).source == str(toml)
    js = tmp_path / "t.machine.json"
    js.write_text(json.dumps(TALLY), encoding="utf-8")
    spec = sm.load_spec(js)
    assert spec.name == "tally" and sm.conformance(spec).ok
    with pytest.raises(sm.SpecError, match="cannot read .*missing.machine.toml"):
        sm.load_spec(tmp_path / "missing.machine.toml")
    bad = tmp_path / "bad.machine.toml"
    bad.write_text("name = [unclosed", encoding="utf-8")
    with pytest.raises(sm.SpecError, match="not valid TOML"):
        sm.load_spec(bad)
    js.write_text("{", encoding="utf-8")
    with pytest.raises(sm.SpecError, match="not valid JSON"):
        sm.load_spec(js)
    bad.write_text("# " + "x" * sm.MAX_SPEC_BYTES, encoding="utf-8")
    with pytest.raises(sm.SpecError, match="spec: larger than"):
        sm.load_spec(bad)
    with pytest.raises(sm.SpecError, match="the spec must be a table"):
        sm.parse_spec([])


def test_write_template_never_overwrites(tmp_path):
    made = sm.write_template(tmp_path)
    assert made == tmp_path / "machine.machine.toml" and made.read_text(encoding="utf-8") == sm.TEMPLATE
    assert sm.gate(sm.load_spec(made)).total == 3
    made.write_text("mine", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not overwriting"):
        sm.write_template(tmp_path)
    with pytest.raises(FileExistsError):
        sm.write_template(made)
    assert made.read_text(encoding="utf-8") == "mine"
    named = sm.write_template(tmp_path / "audit.machine.toml")
    assert named.name == "audit.machine.toml" and sm.find_specs(tmp_path) == [named, made]


# ---------------------------------------------------------------------------------------------- framing

EXAMPLES_TXT = """\
Worked examples. Each: PROGRAM, the source, a lone dot, INPUT, OUTPUT.

PROGRAM
get r1
say r1
.
INPUT 5
OUTPUT 5

PROGRAM
put r1 9
div r2 r1 r3
say r2
.
INPUT
OUTPUT 65535

PROGRAM
put r0 1
.
INPUT 1, 0x10 3
OUTPUT
"""


def test_marker_framing_reads_an_examples_file():
    framing = sm.parse_spec(TALLY).framing
    records = sm.find_records(framing, EXAMPLES_TXT, want_output=True)
    assert [r.program for r in records] == ["get r1\nsay r1\n", "put r1 9\ndiv r2 r1 r3\nsay r2\n", "put r0 1\n"]
    assert [r.input_text for r in records] == ["5", "", "1, 0x10 3"]
    assert [r.output_text for r in records] == ["5", "65535", ""]
    assert sm.parse_inputs(records[2].input_text) == (1, 16, 3)
    assert [r.output_text for r in sm.find_records(framing, EXAMPLES_TXT, want_output=False)] == [None] * 3
    # a program whose end marker has not arrived is not a record yet
    assert len(sm.find_records(framing, EXAMPLES_TXT + "\nPROGRAM\nsay r0\n", want_output=True)) == 3
    with pytest.raises(sm.FramingError, match="program 2 has no input"):
        sm.find_records(framing, "PROGRAM\n.\nINPUT 1\nOUTPUT 1\nPROGRAM\n.\nOUTPUT 2\n", want_output=True)
    with pytest.raises(sm.FramingError, match="program 1 has no expected output"):
        sm.find_records(framing, "PROGRAM\n.\nINPUT 1\n", want_output=True)
    assert sm.find_records(framing, "PROGRAM\n.\nINPUT 1\n", want_output=False)[0].input_text == "1"


def test_regex_framing_and_optional_input():
    spec = sm.parse_spec(tally(framing={"program_re": r"^code: (.*?)$", "input_re": r"^tape:(.*?)$",
                                        "output_re": r"^want: (.*?)$", "prompt": "> ",
                                        "program_start": None, "program_end": None,
                                        "input_prefix": None, "output_prefix": None}))
    body = "intro\ncode: say r1\ntape: 1 2\nwant: 0\ncode: get r1\ntape:\nwant: 65535\n"
    records = sm.find_records(spec.framing, body, want_output=True)
    assert [(r.program, r.input_text, r.output_text) for r in records] == [("say r1", "1 2", "0"), ("get r1", "", "65535")]
    # each record's input is looked for only up to the next program
    with pytest.raises(sm.FramingError, match="program 1 has no input"):
        sm.find_records(spec.framing, "code: say r1\nwant: 0\ncode: get r1\ntape: 4\nwant: 4\n", want_output=True)
    no_input = sm.Framing(program_start="GO", program_end="STOP", output_prefix="=")
    assert sm.find_records(no_input, "GO\nx\nSTOP\n= 3\n", want_output=True) == [sm.Record("x\n", "", "3")]


def test_parse_inputs():
    assert sm.parse_inputs("") == () and sm.parse_inputs("  \n") == ()
    assert sm.parse_inputs("1 2,3 , -4 0x10 0b11") == (1, 2, 3, -4, 16, 3)
    with pytest.raises(sm.FramingError, match="input word 'x' is not an integer"):
        sm.parse_inputs("1 x")


def test_examples_files_are_read_beside_the_spec(tmp_path):
    (tmp_path / "examples.txt").write_text(EXAMPLES_TXT, encoding="utf-8")
    spec = sm.parse_spec(tally(examples_files=["examples.txt"]), base=tmp_path)
    assert [e.name for e in spec.examples] == ["wrap", "zero rules", "examples.txt #1", "examples.txt #2", "examples.txt #3"]
    assert spec.examples[2] == sm.Example("examples.txt #1", "get r1\nsay r1\n", (5,), "5")
    assert sm.conformance(spec).passed == 5
    with pytest.raises(sm.SpecError, match="examples_files: nope.txt: cannot read"):
        sm.parse_spec(tally(examples_files=["nope.txt"]), base=tmp_path)
    (tmp_path / "empty.txt").write_text("nothing framed here\n", encoding="utf-8")
    with pytest.raises(sm.SpecError, match="examples_files: empty.txt: the framing matched no example"):
        sm.parse_spec(tally(examples_files=["empty.txt"]), base=tmp_path)
    (tmp_path / "broken.txt").write_text("PROGRAM\nsay r0\n.\nINPUT x\nOUTPUT 0\n", encoding="utf-8")
    with pytest.raises(sm.SpecError, match="examples_files: broken.txt: input word 'x' is not an integer"):
        sm.parse_spec(tally(examples_files=["broken.txt"]), base=tmp_path)
    with pytest.raises(sm.SpecError, match="'examples.txt' is relative and the spec has no folder"):
        sm.parse_spec(tally(examples_files=["examples.txt"]))
    # a spec shipped in a challenge folder reads only files in its own folder
    spec_dir = tmp_path / "chal"
    (spec_dir / "sub").mkdir(parents=True)
    (spec_dir / "sub" / "more.txt").write_text(EXAMPLES_TXT, encoding="utf-8")
    assert len(sm.parse_spec(tally(examples_files=["sub/more.txt"], examples=[]), base=spec_dir).examples) == 3
    absolute = str(tmp_path / "examples.txt")
    for base in (None, spec_dir):
        with pytest.raises(sm.SpecError, match="is an absolute path; name a file in the spec's folder"):
            sm.parse_spec(tally(examples_files=[absolute], examples=[]), base=base)
    with pytest.raises(sm.SpecError, match=r"'\.\./examples\.txt' leads outside the spec's folder"):
        sm.parse_spec(tally(examples_files=["../examples.txt"], examples=[]), base=spec_dir)
    with pytest.raises(sm.SpecError, match="leads outside the spec's folder"):
        sm.parse_spec(tally(examples_files=["sub/../../examples.txt"], examples=[]), base=spec_dir)
    (spec_dir / "link.txt").symlink_to(tmp_path / "examples.txt")       # a link out is out too
    with pytest.raises(sm.SpecError, match="'link.txt' leads outside the spec's folder"):
        sm.parse_spec(tally(examples_files=["link.txt"], examples=[]), base=spec_dir)


# ------------------------------------------------------------------------------------- conformance gate

def test_conformance_passes_and_the_gate_opens():
    spec = sm.parse_spec(TALLY)
    report = sm.conformance(spec)
    assert (report.total, report.passed, report.ok, report.failures) == (2, 2, True, ())
    assert report.summary() == "2/2 worked examples reproduce"
    assert sm.gate(spec) == report


def test_conformance_ignores_blanks_at_either_end_of_the_run_output():
    # char output that ends in a newline (10) matches an expected text written without it
    spec = machine(io={"format": "char"}, examples=[
        {"name": "line", "program": "say 104\nsay 105\nsay 10", "output": "hi"},
        {"name": "lead", "program": "say 32\nsay 111\nsay 107", "output": "ok"},
    ])
    assert sm.run(spec, "say 104\nsay 105\nsay 10").text == "hi\n"
    report = sm.conformance(spec)
    assert [(r.ok, r.got) for r in report.results] == [(True, "hi"), (True, "ok")]
    assert sm.gate(spec) == report


def test_a_wrong_quirk_fails_the_named_example_and_closes_the_gate():
    spec = sm.parse_spec(tally(quirks={"div_zero": 0}), source="tally.machine.toml")
    report = sm.conformance(spec)
    assert (report.total, report.passed, report.ok) == (2, 1, False)
    (bad,) = report.failures
    assert (bad.index, bad.name, bad.ok, bad.expected, bad.got, bad.error) == (2, "zero rules", False, "65535 9", "0 9", None)
    with pytest.raises(sm.GateRefused) as info:
        sm.gate(spec)
    assert info.value.report == report
    assert str(info.value) == ("tally.machine.toml: 1/2 worked examples reproduce; refusing to play. "
                               "First failure: zero rules: expected '65535 9', got '0 9'")


def test_an_example_that_traps_or_does_not_parse_is_a_failure_not_a_crash():
    spec = sm.parse_spec(tally(quirks={"div_zero": "trap"}, examples=[
        {"name": "traps", "program": "div r0 r1 r2\nsay r0", "output": "65535"},
        {"name": "bad source", "program": "frobnicate r0", "output": ""},
        {"name": "fine", "program": "say r0", "output": " 0 \n"},          # outer blanks do not count
        {"name": "inner blanks do", "program": "say r0\nsay r0", "output": "0  0"},
        {"name": "spins", "program": "times 3\n times 3\n  times 3\n  say r0\n  done\n done\ndone", "output": ""},
    ]))
    report = sm.conformance(spec, fuel=20)
    assert [r.ok for r in report.results] == [False, False, True, False, False]
    assert report.results[0].got is None and "MachineTrap: line 1 `div r0 r1 r2`: division by zero" in report.results[0].error
    assert "ProgramError: line 1 `frobnicate r0`: unknown instruction" in report.results[1].error
    assert report.results[3].got == "0 0" and report.results[3].error is None
    assert "FuelExhausted" in report.results[4].error
    assert sm.conformance(spec).results[4].got == "0 " * 26 + "0"       # with the spec's own fuel it finishes
    with pytest.raises(sm.GateRefused, match="First failure: traps: MachineTrap"):
        sm.gate(spec)


def test_a_spec_with_no_examples_is_refused():
    spec = sm.parse_spec(tally(examples=[]), source="bare.machine.toml")
    report = sm.conformance(spec)
    assert (report.total, report.ok) == (0, False)
    with pytest.raises(sm.GateRefused, match="bare.machine.toml: no worked examples") as info:
        sm.gate(spec)
    assert info.value.report.total == 0


# ---------------------------------------------------------------------------------------- round handler

def test_round_handler_answers_the_last_complete_program():
    handler = sm.RoundHandler(sm.parse_spec(TALLY))
    one = round_text(1, 2, "get r1\nget r2\nadd r0 r1 r2\nsay r0\nsay r1", [65535, 3])
    assert handler("tally audit v1\n" + one) == "2 65535"
    assert handler.rounds == 1
    # a banner that quotes an example before the real round: the last program is the round
    quoted = "example:\nPROGRAM\nsay r7\n.\nINPUT 1\nOUTPUT 0\n" + round_text(2, 2, "get r3\nsay r3", [41])
    assert handler(quoted) == "41"
    assert handler.rounds == 2 and handler.last_text == ""


def test_round_handler_answers_the_last_round_when_two_arrive_in_one_read():
    handler = sm.RoundHandler(sm.parse_spec(TALLY))
    first = round_text(1, 2, "get r1\nsay r1", [7])
    second = round_text(2, 2, "get r1\nget r2\nadd r0 r1 r2\nsay r0", [30, 12])
    assert handler(first + second) == "42"
    assert handler.rounds == 1


def test_round_handler_buffers_until_the_prompt_marker():
    handler = sm.RoundHandler(sm.parse_spec(TALLY))
    whole = round_text(1, 1, "get r1\nsay r1", [12])
    assert handler("welcome\n") is None
    assert handler.last_text == "welcome\n"
    assert handler(whole[:25]) is None                      # mid-program
    assert handler(whole[25:-4]) is None                    # "OUTP" of the marker has arrived, not all of it
    assert handler.rounds == 0
    assert handler(whole[-4:]) == "12"
    assert handler.rounds == 1 and handler.last_text == ""  # answered: nothing is left over
    assert handler("WRONG. session closed.\n") is None      # the verdict is kept for the report
    assert handler.last_text == "WRONG. session closed.\n"


def test_round_handler_never_guesses():
    spec = sm.parse_spec(tally(quirks={"div_zero": "trap"}))
    handler = sm.RoundHandler(spec, fuel=30)
    with pytest.raises(sm.FramingError, match=r"the service is waiting \('OUTPUT>' seen\) but the framing found no complete program"):
        handler("ready?\nOUTPUT> ")
    with pytest.raises(sm.MachineTrap, match="division by zero"):
        handler(round_text(1, 1, "div r0 r1 r2\nsay r0", []))
    with pytest.raises(sm.FuelExhausted):
        handler(round_text(1, 1, "times 3\n times 3\n  times 3\n  say r0\n  done\n done\ndone", []))
    with pytest.raises(sm.ProgramError, match="unknown instruction 'jump'"):
        handler(round_text(1, 1, "jump r0", []))
    with pytest.raises(sm.FramingError, match="program 1 has no input"):
        handler("PROGRAM\nsay r0\n.\nOUTPUT> ")
    with pytest.raises(sm.FramingError, match="input word 'seven' is not an integer"):
        handler("PROGRAM\nsay r0\n.\nINPUT seven\nOUTPUT> ")
    assert handler.rounds == 0


def test_round_handler_needs_a_prompt_marker_and_writes_a_transcript(tmp_path):
    for framing in (None, {"program_start": "P", "program_end": "."}):
        data = tally()
        data.pop("framing")
        if framing:
            data["framing"] = framing
        with pytest.raises(sm.SpecError, match=r"\[framing\] with `prompt`"):
            sm.RoundHandler(sm.parse_spec(data))
    log = tmp_path / "session.log"
    handler = sm.RoundHandler(sm.parse_spec(TALLY), transcript=log)
    first = round_text(1, 2, "get r1\nsay r1", [3])
    second = round_text(2, 2, "say r0\nsay r0", [])
    assert handler(first) == "3" and handler(second) == "0 0"
    assert log.read_text(encoding="utf-8") == first.rstrip(" ") + " 3\n" + second.rstrip(" ") + " 0 0\n"
