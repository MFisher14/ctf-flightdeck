"""B-134: the logic-schematic netlist extractor and simulator (solvers/toolkits/logic_schematic.py).

Every schematic is drawn here with tests/logic_schematic_draw.py (Pillow, lattice coordinates, the
geometry measured on a Logigator export); no editor is run and nothing from a challenge is read. The
event is a made-up one ("ZETA+ CTF 2031", flags ZETA{...}), so nothing in the engine can pass by
knowing a real event's name.

  model      Netlist validation, the bit-parallel simulator, ties, transduce
  sweep      event texts from the profile, input splits, selector schedules, kind assignments, ranking
  pixels     the run, region and long-line helpers against plain-Python references
  extract    drawing -> netlist round trips over scales, themes and offsets; crossings and junctions;
             box orientation; stacked boxes; lamps; decorations; floating pins; shorts; non-circuits;
             what counts as an editor's dot grid; crops; files Pillow must not open
  engine     solve() statuses, what reaches `flags`, what a result with no flags may print, the files
             written, caps and budgets, image discovery, routing and intake under the hook guard
"""
from __future__ import annotations

import builtins
import datetime as dt
import hashlib
import itertools
import json
import os
import random
import stat
import struct
import sys
import zlib
from pathlib import Path

import pytest

from ctf import event, flagfmt

try:
    import logic_schematic as ls
    import logic_schematic_draw as dr
    from PIL import Image, ImageDraw, ImageFont
except ImportError:              # reported as not run by the marker below, never as a pass
    ls = dr = Image = ImageDraw = ImageFont = None

pytestmark = pytest.mark.needs_tool("py:PIL", "py:numpy")

REPO = Path(__file__).resolve().parents[1]
SPACED_BODY = r"[^{}\n]{1,256}"   # a flag body that may hold spaces, as some events' formats allow


def _profile(name="ZETA+ CTF 2031", prefixes=("ZETA",), slug="b134-zeta", body=None):
    return event.parse({
        "slug": slug, "name": name,
        "dates": {"start": dt.date(2031, 1, 1), "end": dt.date(2031, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes), **({"body": body} if body else {})},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()
FF = flagfmt.for_profile(PROFILE)
BRAND = "ZETA+"
MASKS = (0x03, 0x15, 0x1E)
# What the drawn transducer computes under NOR gates, from its specification (not from the gates):
# each character XORed with the mask of selector state 01, 10, 11 in turn.
BODY = "".join(chr(ord(c) ^ m) for c in BRAND for m in MASKS)


def _netlist(circ, kind=None, symbols=None):
    return ls.Netlist(tuple(ls.Gate(g.id, g.ins, kind, (symbols or {}).get(g.id, 0)) for g in circ.gates),
                      tuple(circ.inputs), tuple(circ.outputs), tuple(circ.ties))


def _canon(nl):
    """A netlist up to gate renaming and input order within a gate: inputs, ties, floating nets, the
    multiset of gate signatures and the signature of each output, in order."""
    gmap = {g.id: g for g in nl.gates}
    memo = {}

    def sig(node):
        if node not in memo:
            g = gmap.get(node)
            memo[node] = node if g is None else hashlib.sha1(
                (str(len(g.ins)) + ":" + ",".join(sorted(sig(i) for i in g.ins))).encode()).hexdigest()
        return memo[node]

    for g in nl.order:                      # children first, so the recursion stays shallow
        sig(g.id)
    return (nl.inputs, nl.ties, nl.floating, sorted(sig(g.id) for g in nl.gates), [sig(o) for o in nl.outputs])


def _mini():
    """Six gates over three inputs: a NOT idiom, a three-input box, fan-out, two lamps on one column."""
    c = dr.Circuit(inputs=["in0", "in1", "in2"])
    n0 = c.gate("in0", "in1")
    n1 = c.gate("in1", "in2")
    n2 = c.gate(n0, n1)
    n3 = c.gate(n2, n2)
    n4 = c.gate("in0", n3)
    n5 = c.gate("in0", "in1", "in2")
    c.outputs += [n4, n2, n5]
    return c


@pytest.fixture(scope="module")
def transducer():
    return _netlist(dr.nor_transducer(MASKS))


@pytest.fixture(scope="module")
def board(tmp_path_factory):
    """The transducer drawn as a challenge handout: <dir>/files/board.png."""
    d = tmp_path_factory.mktemp("b134") / "27-logic"
    (d / "files").mkdir(parents=True)
    dr.draw_netlist(dr.nor_transducer(MASKS)).save(d / "files" / "board.png")
    return d


# ================================================================================ model, simulator

def test_gate_kinds_compute_their_truth_tables_bit_parallel():
    nl = ls.Netlist((ls.Gate("g", ("a", "b")), ls.Gate("t", ("a", "b", "c")), ls.Gate("u", ("a",))),
                    ("a", "b", "c"), ("g", "t", "u"))
    a, b, c = 0b00001111, 0b00110011, 0b01010101
    want = {"nor": (0b11000000, 0b10000000, 0b11110000), "nand": (0b11111100, 0b11111110, 0b11110000),
            "and": (0b00000011, 0b00000001, 0b00001111), "or": (0b00111111, 0b01111111, 0b00001111),
            "xor": (0b00111100, 0b01101001, 0b00001111), "xnor": (0b11000011, 0b10010110, 0b11110000)}
    assert set(want) == set(ls.KINDS)
    for kind, (g, t, u) in want.items():
        v = ls.simulate(nl, {"a": a, "b": b, "c": c}, kind, width=8)
        assert (v["g"], v["t"], v["u"]) == (g, t, u), kind


def test_simulate_takes_kinds_per_symbol_and_a_fixed_kind_wins():
    nl = ls.Netlist((ls.Gate("p", ("a", "b"), None, 0), ls.Gate("q", ("a", "b"), None, 1),
                     ls.Gate("r", ("a", "b"), "xor", 0)), ("a", "b"), ("p", "q", "r"))
    v = ls.simulate(nl, {"a": 1, "b": 0}, {0: "and", 1: "or"})
    assert (v["p"], v["q"], v["r"]) == (0, 1, 1)
    assert ls.simulate(nl, {"a": 1, "b": 0}, "nor")["r"] == 1          # r stays xor under a uniform kind
    assert ls.simulate(nl, {"a": 1, "b": 0}, "nor")["p"] == 0
    with pytest.raises(ls.SchematicError, match="gate q .* has no kind"):
        ls.simulate(nl, {"a": 1}, {0: "and"})
    with pytest.raises(ls.SchematicError, match="not an input device: zz"):
        ls.simulate(nl, {"zz": 1}, "nor")
    with pytest.raises(ls.SchematicError, match="unknown gate kind 'imp'"):
        ls.simulate(nl, {"a": 1}, "imp")


def test_tied_input_devices_are_ored_onto_one_net():
    nl = ls.Netlist((ls.Gate("g", ("a", "a")),), ("a", "b"), ("g",), ties=(("b", "a"),))
    assert nl.independent == ("a",) and nl.root("b") == "a"
    assert ls.simulate(nl, {"b": 1}, "or")["g"] == 1
    assert ls.simulate(nl, {"a": 0, "b": 0}, "or")["g"] == 0
    assert ls.simulate(nl, {"a": 0b01, "b": 0b10}, "or", width=2)["g"] == 0b11


@pytest.mark.parametrize("kw, message", [
    (dict(gates=[("g", ("a", "h")), ("h", ("g", "a"))], inputs=("a",)), "combinational loop"),
    (dict(gates=[("g", ("a", "zz"))], inputs=("a",)), "reads undefined node 'zz'"),
    (dict(gates=[("g", ("a",)), ("g", ("a",))], inputs=("a",)), "node name used twice: g"),
    (dict(gates=[("a", ("a",))], inputs=("a",)), "node name used twice: a"),
    (dict(gates=[("g", ())], inputs=("a",)), "gate g has no input"),
    (dict(gates=[("g", ("a",))], inputs=("a",), outputs=("nope",)), "output reads undefined node 'nope'"),
    (dict(gates=[("g", ("a",))], inputs=("a", "b"), ties=(("a", "b"),)), "to an earlier one"),
    (dict(gates=[("g", ("b",))], inputs=("a", "b"), ties=(("b", "a"),)), "reads the tied device 'b'; name its net 'a'"),
    (dict(gates=[("g", ("a",), "nope")], inputs=("a",)), "unknown kind 'nope'"),
    (dict(gates=[("g", ("a",))], inputs=("a", "b", "c"), ties=(("c", "a"), ("c", "b"))), "an input device is tied twice"),
])
def test_a_broken_netlist_is_refused_by_name(kw, message):
    gates = tuple(ls.Gate(*g) for g in kw["gates"])
    with pytest.raises(ls.SchematicError, match=message):
        ls.Netlist(gates, kw["inputs"], kw.get("outputs", ()), kw.get("ties", ()))


def test_a_netlist_over_the_gate_cap_is_refused_by_name(monkeypatch):
    gates = tuple(ls.Gate(f"g{k}", ("a",)) for k in range(4))
    assert len(ls.Netlist(gates, ("a",), ()).gates) == 4         # under the real cap
    monkeypatch.setattr(ls, "MAX_GATES", 3)
    with pytest.raises(ls.SchematicError, match=r"netlist has 4 gates \(cap 3\)"):
        ls.Netlist(gates, ("a",), ())
    assert len(ls.Netlist(gates[:3], ("a",), ()).gates) == 3     # exactly at the cap is fine


def test_netlist_json_round_trip_and_strict_fields(transducer):
    nl = ls.Netlist((ls.Gate("g", ("a", "nc0"), "nand", 2), ls.Gate("h", ("g", "g"))), ("a", "b"), ("h", "g"),
                    ties=(("b", "a"),), floating=("nc0",))
    assert ls.Netlist.from_dict(json.loads(json.dumps(nl.to_dict()))) == nl
    assert ls.Netlist.from_dict(transducer.to_dict()) == transducer
    d = nl.to_dict()
    with pytest.raises(ls.SchematicError, match="unknown netlist field: wires"):
        ls.Netlist.from_dict({**d, "wires": []})
    with pytest.raises(ls.SchematicError, match="'outputs' must be a list"):
        ls.Netlist.from_dict({k: v for k, v in d.items() if k != "outputs"})
    with pytest.raises(ls.SchematicError, match="each gate is"):
        ls.Netlist.from_dict({**d, "gates": [{"i": 0, "a": "a", "b": "a"}]})
    with pytest.raises(ls.SchematicError, match="a netlist is a JSON object"):
        ls.Netlist.from_dict([1, 2])
    # node names are strings: a number, or a string where a list belongs, is refused, not coerced
    for field, bad in (("inputs", ["a", 7]), ("outputs", [7]), ("floating", "nc0"), ("floating", [0])):
        with pytest.raises(ls.SchematicError, match="inputs, outputs and floating are lists of node names"):
            ls.Netlist.from_dict({**d, field: bad})


def _rev(x, bits):
    return int(format(x, f"0{bits}b")[::-1], 2)


def test_transduce_feeds_characters_and_reads_one_value_per_selector_state():
    data = tuple(f"d{k}" for k in range(7))
    nl = ls.Netlist(tuple(ls.Gate(f"x{k}", (data[k], "s"), "xor") for k in range(7)), ("s",) + data,
                    tuple(f"x{k}" for k in range(7)))
    states = ((0,), (1,))
    plain = ls.transduce(nl, "ab", ls.Readout(("s",), data, states), {})
    assert plain == [0x61, 0x61 ^ 0x7F, 0x62, 0x62 ^ 0x7F]
    lsb_in = ls.transduce(nl, "ab", ls.Readout(("s",), data, states, msb_first=False), {})
    assert lsb_in == [_rev(0x61, 7), _rev(0x61, 7) ^ 0x7F, _rev(0x62, 7), _rev(0x62, 7) ^ 0x7F]
    assert lsb_in != plain
    lsb_out = ls.transduce(nl, "ab", ls.Readout(("s",), data, states, out_msb_first=False), {})
    assert lsb_out == [_rev(v, 7) for v in plain] and lsb_out != plain
    assert ls.transduce(nl, "ab", ls.Readout(("s",), data, ((1,),)), {}) == [0x61 ^ 0x7F, 0x62 ^ 0x7F]
    assert ls.transduce(nl, "", ls.Readout(("s",), data, states), {}) == []
    with pytest.raises(ls.SchematicError, match="does not fit 7 data lines"):
        ls.transduce(nl, "\xe9", ls.Readout(("s",), data, states), {})


# ========================================================================================= sweep

def test_event_texts_come_from_the_profile_with_the_brands_punctuation():
    assert ls.event_texts(PROFILE) == ["ZETA+", "ZETA", "zeta+", "zeta", "ZETA+ CTF", "ZETA+ CTF 2031",
                                       "b134-zeta", "B134-ZETA"]
    owl = _profile(name="Night Owl Capture The Flag 2030", prefixes=("owl", "flag"), slug="nightowl")
    assert ls.event_texts(owl, extra=["  given  first ", "owl"]) == [
        "given first", "owl", "Night Owl", "Night", "flag", "night owl", "NIGHT OWL", "OWL", "FLAG",
        "Night Owl Capture The Flag", "Night Owl Capture The Flag 2030", "nightowl", "NIGHTOWL"]
    assert ls.event_texts(_profile(name="x" * 80, prefixes=(), slug="s")) == ["s", "S"]   # over-long texts are left out


def test_input_splits_keep_seven_or_eight_data_lines_and_never_cut_a_tie():
    ten = ls.Netlist((), tuple(f"in{k}" for k in range(10)), (), ties=(("in3", "in2"),))
    seven = ("in2", "in4", "in5", "in6", "in7", "in8", "in9")
    assert ls.input_splits(ten) == [
        (("in0", "in1"), seven),
        (("in8", "in9"), ("in0", "in1", "in2", "in4", "in5", "in6", "in7")),
        (("in0",), ("in1",) + seven),
        (("in9",), ("in0", "in1", "in2", "in4", "in5", "in6", "in7", "in8")),
    ]                                           # three leading selectors would cut in3 off in2: not offered
    eight = ls.Netlist((), tuple(f"in{k}" for k in range(8)), ())
    assert ls.input_splits(eight) == [
        (("in0",), tuple(f"in{k}" for k in range(1, 8))),
        (("in7",), tuple(f"in{k}" for k in range(7))),
        ((), tuple(f"in{k}" for k in range(8))),
    ]
    assert ls.input_splits(ls.Netlist((), ("a", "b", "c"), ())) == []
    # eleven devices: three leading selectors would leave seven data lines, but in3 is wired onto in2
    eleven = ls.Netlist((), tuple(f"in{k}" for k in range(11)), (), ties=(("in3", "in2"),))
    assert ls.input_splits(eleven) == [
        (("in0", "in1"), ("in2", "in4", "in5", "in6", "in7", "in8", "in9", "in10")),
        (("in9", "in10"), ("in0", "in1", "in2", "in4", "in5", "in6", "in7", "in8")),
        (("in8", "in9", "in10"), ("in0", "in1", "in2", "in4", "in5", "in6", "in7")),
    ]


def test_selector_schedules_start_with_the_non_zero_states_counting_up():
    assert ls.selector_schedules(2) == [
        ((0, 1), (1, 0), (1, 1)), ((1, 0), (0, 1), (1, 1)), ((1, 1), (1, 0), (0, 1)), ((1, 1), (0, 1), (1, 0)),
        ((0, 0), (0, 1), (1, 0), (1, 1)), ((0, 0), (1, 0), (0, 1), (1, 1)),
        ((0, 0),), ((0, 1),), ((1, 0),), ((1, 1),)]
    assert ls.selector_schedules(1) == [((1,),), ((0,), (1,)), ((0,),)]
    assert ls.selector_schedules(0) == [((),)]


def test_kind_assignments_are_uniform_first_then_mixed_for_up_to_three_symbols():
    def nl(nsym, fixed=None):
        return ls.Netlist(tuple(ls.Gate(f"g{k}", ("a",), fixed, k) for k in range(nsym)), ("a",), ())
    one = ls.kind_assignments(nl(1))
    assert one == [((0, k),) for k in ls.KINDS] and one[0] == ((0, "nor"),)
    two = ls.kind_assignments(nl(2))
    assert two[:6] == [((0, k), (1, k)) for k in ls.KINDS] and len(two) == 36 and len(set(two)) == 36
    assert two[6] == ((0, "nor"), (1, "nand"))
    assert len(ls.kind_assignments(nl(3))) == 216
    assert ls.kind_assignments(nl(4)) == [tuple((s, k) for s in range(4)) for k in ls.KINDS]
    assert ls.kind_assignments(nl(2, fixed="nor")) == [()]
    assert ls.kind_assignments(nl(1), kinds=("xor", "nor")) == [((0, "xor"),), ((0, "nor"),)]
    with pytest.raises(ls.SchematicError, match="unknown gate kind 'imp'"):
        ls.kind_assignments(nl(1), kinds=("imp",))


def test_sweep_reads_the_planted_body_from_the_full_brand_under_nor(transducer):
    sw = ls.sweep(transducer, ls.event_texts(PROFILE), flag_format=FF)
    top = sw.readings[0]
    assert top.stream == BODY and top.text == BRAND and top.kinds == ((0, "nor"),) and top.flags == ()
    assert top.readout == ls.Readout(("in0", "in1"), ("in2", "in4", "in5", "in6", "in7", "in8", "in9"),
                                     ((0, 1), (1, 0), (1, 1)), True, True)
    streams = [r.stream for r in sw.readings]
    assert len(streams) == len(set(streams))                      # one reading per distinct stream
    # the flag prefix alone (the brand without its '+') reads a strict prefix: reported, but after
    short = BODY[:-len(MASKS)]
    assert streams.index(short) > 0 and sw.readings[streams.index(short)].text == "ZETA"
    assert not sw.truncated and sw.tried > 100
    # printability is what rules the other gate kinds out for this readout
    for kind in ("nand", "and", "or", "xor", "xnor"):
        vals = ls.transduce(transducer, BRAND, top.readout, kind)
        assert any(not 0x20 <= v <= 0x7E for v in vals), kind


def test_sweep_reports_every_kind_that_reads_printable_best_kind_first():
    # buffers g(d, d) on every bit but the lowest, which is g(d0, d1): AND and OR both read printable text
    devs = tuple(f"in{k}" for k in range(8))                      # in0 = bit 7 ... in7 = bit 0
    gates = [ls.Gate(f"b{k}", (devs[k], devs[k])) for k in range(7)] + [ls.Gate("low", ("in7", "in6"))]
    nl = ls.Netlist(tuple(gates), devs, tuple(g.id for g in gates))
    sw = ls.sweep(nl, ls.event_texts(PROFILE), flag_format=FF)
    by_stream = {r.stream: r for r in sw.readings}
    assert by_stream["ZDT@+"].kinds == ((0, "and"),) and by_stream["ZDT@+"].text == BRAND
    assert by_stream["[ETA+"].kinds == ((0, "or"),) and by_stream["[ETA+"].text == BRAND
    order = [r.stream for r in sw.readings]
    assert order.index("ZDT@+") < order.index("ZDT@") < order.index("[ETA+")     # kind, then text
    kinds_seen = [r.kinds[0][1] for r in sw.readings]
    assert kinds_seen == sorted(kinds_seen, key=ls.KINDS.index)                  # KINDS order, NOR first
    assert {"and", "or"} <= set(kinds_seen)


def test_sweep_drops_readings_that_only_echo_the_input():
    devs = tuple(f"in{k}" for k in range(8))
    nl = ls.Netlist(tuple(ls.Gate(f"b{k}", (devs[k], devs[k])) for k in range(8)), devs, tuple(f"b{k}" for k in range(8)))
    # under AND or OR every lamp repeats its data line: the only printable readings are the text itself
    sw = ls.sweep(nl, [BRAND], kinds=("and", "or"))
    assert sw.readings == ()
    assert any("printable reading(s) only echoed the input" in n for n in sw.notes)
    assert ls.transduce(nl, BRAND, ls.Readout((), devs, ((),)), "and") == [ord(c) for c in BRAND]   # it was an echo
    # NOR inverts instead, which is a reading of its own (seven data lines, the eighth held high)
    inverted = "".join(chr(ord(c) ^ 0x7F) for c in BRAND)
    assert ls.sweep(nl, [BRAND], kinds=("nor",)).readings[0].stream == inverted


def test_sweep_drops_a_stream_that_repeats_one_character_and_counts_printable_strictly():
    # constants only: 0 = NOR(x, NOT x), 1 = NOT 0; the lamps always show 0b01000001, whatever is fed
    devs = tuple(f"in{k}" for k in range(8))
    gates = [ls.Gate("nx", ("in0", "in0")), ls.Gate("zero", ("in0", "nx")), ls.Gate("one", ("zero", "zero"))]
    nl = ls.Netlist(tuple(gates), devs, ("zero", "one", "zero", "zero", "zero", "zero", "zero", "one"))
    assert ls.transduce(nl, "xy", ls.Readout((), devs, ((),)), "nor") == [0x41, 0x41]
    sw = ls.sweep(nl, [BRAND], kinds=("nor",))
    assert sw.readings == () and any("repeated one character" in n for n in sw.notes)
    assert [r.stream for r in ls.sweep(nl, ["x"], kinds=("nor",)).readings] == ["A"]     # one character proves nothing either way
    assert ls._printable([0x20, 0x7E]) and not ls._printable([0x41, 0x1F]) and not ls._printable([0x7F])
    assert not ls._printable([]) and not ls._printable([0x41, 0x100])


def test_sweep_tries_mixed_kinds_when_two_symbols_are_drawn():
    devs = tuple(f"in{k}" for k in range(8))
    gates = [ls.Gate(f"b{k}", (devs[k], devs[k]), None, 1) for k in range(7)] + [ls.Gate("low", ("in7", "in7"), None, 0)]
    nl = ls.Netlist(tuple(gates), devs, tuple(g.id for g in gates))
    sw = ls.sweep(nl, [BRAND], flag_format=FF)
    flipped = "".join(chr(ord(c) ^ 1) for c in BRAND)             # buffers (symbol 1) and one inverter (symbol 0)
    hit = next(r for r in sw.readings if r.stream == flipped)
    assert hit.kinds == ((0, "nor"), (1, "and")) and hit.kinds_text() == "symbol 0 nor, symbol 1 and"
    for kind in ls.KINDS:                                         # no single kind for both symbols reads it
        assert "".join(map(chr, ls.transduce(nl, BRAND, hit.readout, kind))) != flipped, kind
    uniform = [r for r in sw.readings if len({k for _, k in r.kinds}) == 1]
    assert uniform and sw.readings.index(uniform[-1]) < sw.readings.index(hit)   # one kind for all is tried first
    four = ls.Netlist(tuple(ls.Gate(f"b{k}", (devs[k], devs[k]), None, k % 4) for k in range(8)), devs,
                      tuple(f"b{k}" for k in range(8)))
    assert any("4 box symbols: only one kind for all of them" in n for n in ls.sweep(four, [BRAND]).notes)


def _pla(pairs, states=((0, 1), (1, 0), (1, 1))):
    """A NOR-only network over in0, in1 (selector) and in2..in8 (a 7-bit character, top bit first)
    that maps each (character of text, selector state) to the matching character of target, for every
    (text, target) pair. Built as one many-input NOR per (character, state) and one per output bit."""
    c = dr.Circuit(inputs=[f"in{k}" for k in range(9)])
    sel, data = ["in0", "in1"], [f"in{k}" for k in range(2, 9)]
    inv = {x: c.gate(x, x) for x in sel + data}
    hit: dict = {}
    for text, target in pairs:
        assert len(target) == len(text) * len(states)
        for ci, ch in enumerate(text):
            for si, st in enumerate(states):
                assert (ch, st) not in hit, "a character may appear once"
                off = [inv[sel[k]] if st[k] else sel[k] for k in range(2)]
                off += [inv[data[k]] if (ord(ch) >> (6 - k)) & 1 else data[k] for k in range(7)]
                hit[(ch, st)] = (c.gate(*off), ord(target[ci * len(states) + si]))
    for bit in range(7, -1, -1):
        on = [g for g, val in hit.values() if (val >> bit) & 1]
        c.outputs.append(c.gate(c.gate(*on), c.gate(*on)) if on else c.gate("in1", inv["in1"]))
    return c


def test_a_reading_that_holds_an_event_format_flag_ranks_first():
    flag = f"{PROFILE.flag.prefixes[0]}{{n0r_g4t3s}}"
    assert len(flag) == 15 and FF.is_flag(flag)
    nl = _netlist(_pla([("owls!", "plain_text_15ch"), (BRAND, flag)]))
    sw = ls.sweep(nl, ["owls!", BRAND], flag_format=FF)
    assert sw.readings[0].stream == flag and sw.readings[0].flags == (flag,) and sw.readings[0].text == BRAND
    plain = next(r for r in sw.readings if r.stream == "plain_text_15ch")
    assert plain.flags == () and plain.text == "owls!"
    # without a flag format the text order alone decides, so the flag's rank came from the format match
    assert ls.sweep(nl, ["owls!", BRAND]).readings[0].stream == "plain_text_15ch"


def test_sweep_skips_a_text_too_wide_for_the_data_lines_instead_of_failing(transducer):
    wide = "Z\xc9TA+"                                             # 0xC9 does not fit seven data lines
    sw = ls.sweep(transducer, [wide, BRAND], flag_format=FF)
    by_stream = {r.stream: r for r in sw.readings}
    assert by_stream[BODY].text == BRAND and len(by_stream[BODY].readout.data) == 7
    fed_wide = [r for r in sw.readings if r.text == wide]
    assert fed_wide and all(len(r.readout.data) == 8 for r in fed_wide)           # fed only where it fits
    # ... and the skip is said, with the text and the width it did not fit
    assert ("1 text(s) hold a character too wide for the data lines of a split and were not fed there "
            f"(first: {wide!r} on 7 lines)") in sw.notes
    assert not any("too wide" in n for n in ls.sweep(transducer, [BRAND], flag_format=FF).notes)


def test_sweep_stops_at_the_hypothesis_cap_and_says_so(transducer):
    sw = ls.sweep(transducer, ls.event_texts(PROFILE), flag_format=FF, max_hypotheses=5)
    assert sw.tried == 5 and sw.truncated
    assert any("stopped at the cap of 5 hypotheses" in n for n in sw.notes)


def test_sweep_stops_when_the_callers_budget_runs_out_and_says_so(transducer):
    asked = []

    def stop():                                                   # the budget runs out at the eighth question
        asked.append(1)
        return len(asked) > 7
    sw = ls.sweep(transducer, ls.event_texts(PROFILE), flag_format=FF, stop=stop)
    assert sw.tried == 7 and sw.truncated and len(asked) == 8     # asked before every hypothesis, not after
    assert "stopped by the time budget after 7 hypotheses" in sw.notes
    assert not any("cap of" in n for n in sw.notes)
    full = ls.sweep(transducer, ls.event_texts(PROFILE), flag_format=FF, stop=lambda: False)
    assert not full.truncated and full.tried > 100 and full.readings[0].stream == BODY


def test_readings_rank_by_selector_schedule_before_bit_order():
    # One selector line s and seven data lines; every kind is drawn, so only the readout is swept.
    #   s = 1: the lamps show the character with its bits reversed, and its second-lowest lamp flipped
    #   s = 0: the lamps show the character with its lowest bit flipped
    # So the first schedule (s = 1 alone) reads printable only when the data are fed lowest bit first
    # (the second bit order), and the last schedule (s = 0 alone) reads printable in the first bit order.
    s, d = "in0", [f"in{k}" for k in range(1, 8)]
    gates = [ls.Gate("ns", (s, s), "nor")]
    outs = []
    for k in range(7):
        gates += [ls.Gate(f"a{k}", ("ns", d[k]), "and"), ls.Gate(f"b{k}", (s, d[6 - k]), "and"),
                  ls.Gate(f"m{k}", (f"a{k}", f"b{k}"), "or")]
        outs.append(f"m{k}")
    gates += [ls.Gate("low", ("m6", "ns"), "xor"), ls.Gate("second", ("m5", s), "xor")]
    outs[6], outs[5] = "low", "second"
    nl = ls.Netlist(tuple(gates), (s, *d), tuple(outs))
    by_state_one, by_state_zero = "".join(chr(ord(c) ^ 2) for c in BRAND), "".join(chr(ord(c) ^ 1) for c in BRAND)
    sw = ls.sweep(nl, [BRAND])
    by_stream = {r.stream: r for r in sw.readings}
    one, zero = by_stream[by_state_one], by_stream[by_state_zero]
    assert (one.readout.states, one.readout.msb_first, one.readout.out_msb_first) == (((1,),), False, True)
    assert (zero.readout.states, zero.readout.msb_first, zero.readout.out_msb_first) == (((0,),), True, True)
    assert one.readout.selectors == zero.readout.selectors == (s,) and one.kinds == zero.kinds == ()
    schedules = ls.selector_schedules(1)
    assert schedules.index(one.readout.states) < schedules.index(zero.readout.states)
    assert sw.readings.index(one) < sw.readings.index(zero)       # the schedule decides, not the bit order


def test_sweep_names_why_no_readout_fits():
    nine = ls.Netlist(tuple(ls.Gate(f"g{k}", ("a",)) for k in range(9)), ("a",), tuple(f"g{k}" for k in range(9)))
    sw = ls.sweep(nine, [BRAND])
    assert sw.readings == () and sw.tried == 0 and "9 output device(s): a byte readout needs 1 to 8" in sw.notes[0]
    few = ls.Netlist((ls.Gate("g", ("a", "b")),), ("a", "b", "c"), ("g",))
    sw = ls.sweep(few, [BRAND])
    assert sw.tried == 0 and "3 independent input(s): no split leaves 7 or 8 data lines" in sw.notes[0]


# ========================================================================== pixels: runs, regions

def _random_mask(rng, h, w, density):
    import numpy as np
    return np.array([[rng.random() < density for _ in range(w)] for _ in range(h)], dtype=bool).reshape(h, w)


def _flood(mask, diagonal):
    """Reference labelling, one pixel at a time: {label: set of (y, x)}, labels from 1 in raster order
    of each region's first pixel."""
    h, w = mask.shape
    steps = [(0, 1), (1, 0), (0, -1), (-1, 0)] + ([(1, 1), (1, -1), (-1, 1), (-1, -1)] if diagonal else [])
    seen, regions = set(), {}
    for y in range(h):
        for x in range(w):
            if mask[y, x] and (y, x) not in seen:
                todo, cells = [(y, x)], set()
                seen.add((y, x))
                while todo:
                    cy, cx = todo.pop()
                    cells.add((cy, cx))
                    for dy, dx in steps:
                        q = (cy + dy, cx + dx)
                        if 0 <= q[0] < h and 0 <= q[1] < w and mask[q] and q not in seen:
                            seen.add(q)
                            todo.append(q)
                regions[len(regions) + 1] = cells
    return regions


@pytest.mark.parametrize("diagonal", [False, True], ids=["4-connected", "8-connected"])
def test_regions_match_a_pixel_by_pixel_flood_fill(diagonal):
    import numpy as np
    rng = random.Random(11)
    shapes = [(1, 1), (1, 9), (9, 1), (2, 2)] + [(rng.randrange(2, 24), rng.randrange(2, 24)) for _ in range(40)]
    joined_by_a_corner = 0
    for h, w in shapes:
        mask = _random_mask(rng, h, w, rng.choice([0.25, 0.5, 0.75]))
        want = _flood(mask, diagonal)
        joined_by_a_corner += len(_flood(mask, False)) - len(_flood(mask, True))
        reg = ls._Regions(mask, diagonal=diagonal)
        assert reg.n == len(want)
        border = np.flatnonzero(reg.on_border()).tolist()
        for i, cells in want.items():                  # the same numbering: raster order of the first pixel
            ys, xs = [y for y, _ in cells], [x for _, x in cells]
            assert (reg.y0[i], reg.y1[i], reg.x0[i], reg.x1[i]) == (min(ys), max(ys) + 1, min(xs), max(xs) + 1)
            assert reg.area[i] == len(cells)
            crop = reg.crop(i)
            assert {(int(y) + min(ys), int(x) + min(xs)) for y, x in zip(*np.nonzero(crop))} == cells
            assert (i in border) == any(y in (0, h - 1) or x in (0, w - 1) for y, x in cells)
    assert joined_by_a_corner > 50                     # the two connectivities really differ on these masks
    empty = ls._Regions(np.zeros((5, 7), bool), diagonal=diagonal)
    assert empty.n == 0 and not empty.on_border().any()


def test_regions_follow_a_winding_shape_and_keep_touching_shapes_apart():
    import numpy as np
    # a spiral one pixel wide: one region, whatever order its runs are met in; a comb beside it: one
    # region too; and the two stay apart although only a one-pixel gap separates them
    spiral = ["#########.#.#.#",
              "........#.#.#.#",
              "#######.#.#.#.#",
              "#.....#.#.#.#.#",
              "#.###.#.#.#.#.#",
              "#.#...#.#.#.#.#",
              "#.#####.#.#.#.#",
              "#.......#.#####",
              "#########......"]
    mask = np.array([[c == "#" for c in row] for row in spiral])
    reg = ls._Regions(mask)
    assert reg.n == 2 and reg.area.tolist() == [0, sum(row[:9].count("#") for row in spiral), 3 * 8 + 2]
    assert (reg.y0[1], reg.y1[1], reg.x0[1], reg.x1[1]) == (0, 9, 0, 9)
    assert (reg.y0[2], reg.y1[2], reg.x0[2], reg.x1[2]) == (0, 8, 10, 15)
    assert np.array_equal(reg.crop(2), mask[0:8, 10:15]) and np.array_equal(reg.crop(1), mask[:, 0:9])
    # the background: the spiral's inside, the lane between the shapes, and the two slots of the comb
    back = ls._Regions(~mask)
    assert back.n == 4 and sorted(back.area[1:].tolist()) == [7, 7, 9 + 5, 9 * 9 - int(reg.area[1])]
    assert back.on_border().tolist() == [False, True, True, True, True]


def _long_reference(mask, length):
    """Pixels lying in a horizontal run of at least `length` pixels, one row at a time."""
    out = [[False] * len(row) for row in mask]
    for y, row in enumerate(mask):
        x = 0
        while x < len(row):
            if row[x]:
                e = x
                while e < len(row) and row[e]:
                    e += 1
                if e - x >= length:
                    out[y][x:e] = [True] * (e - x)
                x = e
            else:
                x += 1
    return out


def test_long_runs_keep_exactly_the_runs_of_the_asked_length_or_more():
    import numpy as np
    rng = random.Random(4)
    for _ in range(30):
        h, w = rng.randrange(1, 20), rng.randrange(1, 30)
        mask = _random_mask(rng, h, w, 0.75)
        for length in (1, 3, 5, 7):
            want = np.array(_long_reference(mask.tolist(), length), dtype=bool).reshape(h, w)
            assert np.array_equal(ls._long_runs(ls._runs(mask), (h, w), length), want)
            assert ls._long_share(ls._runs(mask), h, length).tolist() == want.sum(axis=1).tolist()
            # along columns: the runs of the transposed mask, turned back
            want_v = np.array(_long_reference(mask.T.tolist(), length), dtype=bool).reshape(w, h).T
            assert np.array_equal(ls._long_runs(ls._runs(mask.T), (w, h), length).T, want_v)
    row = np.array([[1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1]], dtype=bool)
    # an even length counts as the next odd one (the window of an opening is centred): 4 keeps 5 and up
    assert ls._long_runs(ls._runs(row), row.shape, 4).tolist() == [[0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0]]
    assert ls._long_share(ls._runs(row), 1, 4).tolist() == [5]
    assert ls._long_runs(ls._runs(row), row.shape, 3).sum() == 12
    rr, start, end = ls._runs(np.array([[1, 0, 1, 1], [0, 0, 0, 0], [1, 1, 1, 1]], dtype=bool))
    assert (rr.tolist(), start.tolist(), end.tolist()) == ([0, 0, 2], [0, 2, 0], [1, 4, 4])   # a run never crosses a row end


def test_an_image_with_too_many_ink_runs_is_refused_by_name(board, monkeypatch):
    monkeypatch.setattr(ls, "MAX_RUNS", 40)
    with pytest.raises(ls.NotSchematic, match=r"too fragmented to be a circuit drawing \(over 40 runs of ink\)"):
        ls.extract(board / "files" / "board.png")


# ================================================================================ image -> netlist

def test_the_drawn_transducer_is_read_back_gate_for_gate(board, transducer):
    ex = ls.extract(board / "files" / "board.png")
    assert _canon(ex.netlist) == _canon(transducer)
    assert ex.netlist.ties == (("in3", "in2"),) and len(ex.netlist.inputs) == 10 and len(ex.netlist.outputs) == 8
    assert ex.editor == "logigator-like" and ex.pitch == 16 and ex.wire_width == 1 and ex.issues == ()
    wired = sum(len(g.ins) for g in transducer.gates) + len(transducer.gates)      # every gate here is read
    assert ex.stats["pins"] == wired and ex.stats["symbols"] == 1 and ex.stats["rejected_boxes"] == 0
    assert ex.stats["crossings"] > 100 and ex.stats["dots"] > 1000
    assert len(ex.gate_boxes) == len(transducer.gates)
    assert all((x1 - x0, y1 - y0) == (48, 32) for x0, y0, x1, y1 in ex.gate_boxes)   # 3 x 2 cells of 16px
    assert [x for x, _ in ex.input_at] == sorted(x for x, _ in ex.input_at)           # a row: left to right
    assert [y for _, y in ex.output_at] == sorted(y for _, y in ex.output_at)         # a column: top down
    det = ls.detect(board / "files" / "board.png")
    assert (det.is_schematic, det.supported, det.editor, det.gates, det.pitch) == (True, True, "logigator-like", 38, 16)


@pytest.mark.parametrize("kw, editor", [
    (dict(pitch=64, w=4, shift=(-2, 2)), "logigator-like"),       # the scale and wire offsets of the real export
    (dict(pitch=24, w=2), "logigator-like"),
    (dict(pitch=16, w=1, theme="light"), "logigator-like"),       # one colour: symbols are ink islands
    (dict(pitch=20, w=2, theme="blueprint", dots=False), "box-and-wire"),
    (dict(pitch=16, w=1, junction_squares=False), "logigator-like"),   # a T joins without a square
], ids=["p64-offset", "p24", "one-colour", "no-dots", "bare-tees"])
def test_extraction_does_not_depend_on_scale_colours_or_offsets(tmp_path, kw, editor):
    circ = _mini()
    path = dr.draw_netlist(circ, **kw).save(tmp_path / "mini.png")
    ex = ls.extract(path)
    assert _canon(ex.netlist) == _canon(_netlist(circ))
    assert ex.editor == editor and ex.pitch == kw["pitch"] and ex.wire_width == kw["w"] and ex.issues == ()
    assert [g.ins for g in ex.netlist.gates][5] == ("in0", "in1", "in2")           # three pins, top to bottom
    assert bool(ex.stats["dots"]) == kw.get("dots", True)


def test_two_symbols_drawn_are_two_symbol_classes(tmp_path):
    circ = _mini()
    path = dr.draw_netlist(circ, symbols={"n1": "&", "n4": "&"}).save(tmp_path / "two.png")
    ex = ls.extract(path)
    assert ex.stats["symbols"] == 2 and ex.netlist.symbols == (0, 1)
    assert [g.symbol for g in ex.netlist.gates] == [0, 1, 0, 0, 1, 0]             # gates are numbered top down


def _cross(tmp_path, junction):
    """in0 and in1 feed one box; in1's wire crosses in0's twice. With `junction`, a square sits on
    the first crossing."""
    c = dr.Canvas(17, 11)
    a, b = c.input_cell(2, 0), c.input_cell(5, 0)
    ins, out = c.box(9, 4)
    c.wire(a, (2, 5), ins[1])
    c.wire(b, (5, 7), (7, 7), (7, 4), ins[0])
    if junction:
        c.junction(5, 5)
    c.wire(out, (14, 4))
    c.lamp(14, 4)
    return ls.extract(c.save(tmp_path / f"cross{int(junction)}.png"))


def test_a_plain_crossing_passes_through_and_a_junction_square_joins(tmp_path):
    plain = _cross(tmp_path, junction=False)
    assert plain.netlist.gates[0].ins == ("in1", "in0") and plain.netlist.ties == ()
    assert plain.stats["crossings"] == 2 and plain.netlist.outputs == ("g0",)
    assert plain.stats["junctions"] == 0                          # corners join wires but are not junctions
    joined = _cross(tmp_path, junction=True)
    assert joined.netlist.ties == (("in1", "in0"),) and joined.netlist.gates[0].ins == ("in0", "in0")
    assert joined.stats["crossings"] == 1 and joined.stats["junctions"] == 1


def test_the_editor_is_named_by_cut_corners_and_dots_together(tmp_path):
    def two_input(clip, dots):
        c = dr.Canvas(15, 9, dots=dots)
        a, b = c.input_cell(2, 0), c.input_cell(4, 0)
        ins, out = c.box(7, 3, clip=clip)
        c.wire(a, (2, 3), ins[0])
        c.wire(b, (4, 4), ins[1])
        c.wire(out, (12, 3))
        c.lamp(12, 3)
        return ls.extract(c.save(tmp_path / f"two-{clip}-{dots}.png"))
    cut = two_input(clip=True, dots=True)
    assert cut.editor == "logigator-like" and cut.stats["dots"] > 50
    for clip, dots in ((False, True), (True, False), (False, False)):    # either sign alone is not enough
        ex = two_input(clip, dots)
        assert ex.editor == "box-and-wire" and bool(ex.stats["dots"]) == dots
        assert _canon(ex.netlist) == _canon(cut.netlist) and ex.netlist.gates[0].ins == ("in0", "in1")


def test_a_frame_around_a_mark_as_big_as_itself_is_not_a_component(tmp_path):
    circ = _mini()
    c = dr.draw_netlist(circ, pitch=16, w=1)
    assert (c.cols, c.rows) == (22, 34)
    c.outline(1, 29, 4, 3)                                        # a frame in the free corner, wired to nothing ...
    x0, y0, x1, y1 = 16, 29 * 16, 5 * 16, 32 * 16
    c.d.line((x0 + 3, (y0 + y1) // 2, x1 - 4, (y0 + y1) // 2), fill=c.sym)   # ... holding a cross that spans it
    c.d.line(((x0 + x1) // 2, y0 + 3, (x0 + x1) // 2, y1 - 4), fill=c.sym)
    ex = ls.extract(c.save(tmp_path / "frame.png"))
    # a symbol is smaller than its box: the frame is never a box candidate, so nothing has to be rejected
    assert ex.stats["rejected_boxes"] == 0 and len(ex.gate_boxes) == 6
    assert _canon(ex.netlist) == _canon(_netlist(circ)) and ex.issues == ()


def test_box_orientation_follows_the_pins_downward_and_leftward_boxes(tmp_path):
    c = dr.Canvas(18, 15)
    a, b = c.input_cell(12, 0), c.input_cell(13, 0)
    down_in, down_out = c.box(12, 3, out="S")                     # top right: inputs on top, output bottom right
    c.wire(a, down_in[0])
    c.wire(b, down_in[1])
    left_in, left_out = c.box(4, 10, out="W")                     # bottom left: inputs on the right, output on the left
    c.wire(down_out, (13, 8), (9, 8), (9, 10), left_in[0])
    c.wire((9, 10), (9, 11), left_in[1])
    c.junction(9, 10)
    c.wire(left_out, (1, 10))
    c.lamp(1, 10)
    ex = ls.extract(c.save(tmp_path / "turn.png"))
    nl = ex.netlist
    # gates are numbered in reading order (top to bottom, then left to right): the upper box is g0
    assert [(g.id, g.ins) for g in nl.gates] == [("g0", ("in0", "in1")), ("g1", ("g0", "g0"))]
    assert nl.inputs == ("in0", "in1") and nl.outputs == ("g1",)
    assert ex.gate_boxes[0] == (192, 48, 224, 96) and ex.gate_boxes[1] == (64, 160, 112, 192)   # 2x3 and 3x2 cells


def test_bare_wire_ends_are_devices_ordered_along_their_wider_spread(tmp_path):
    c = dr.Canvas(14, 9)
    ins, out = c.box(6, 3, ins=3)
    for pin, x in zip(ins, (4, 2, 0)):                            # three wires that just end, stepping down and left
        c.wire((x, pin[1]), pin)
    c.wire(out, (11, 3))                                          # and the output wire ends bare too
    ex = ls.extract(c.save(tmp_path / "bare.png"))
    # the ends spread wider (4 cells) than tall (2 cells): left to right, so in0 is the lowest wire
    # (no vertical wire here, so the x phase comes from the box edges alone and is good to a pixel)
    assert [y for _, y in ex.input_at] == [88, 72, 56]
    assert all(abs(x - want) <= 1 for (x, _), want in zip(ex.input_at, (8, 40, 72)))
    assert ex.netlist.inputs == ("in0", "in1", "in2") and ex.netlist.gates[0].ins == ("in2", "in1", "in0")
    assert ex.netlist.outputs == ("g0",) and ex.output_at[0][1] == 56 and abs(ex.output_at[0][0] - 184) <= 1


def _one_input(tmp_path, clip_side):
    """An input cell on the left, a one-input box, a lamp on the right; the box's cut corners are on
    `clip_side` (None: a plain rectangle)."""
    c = dr.Canvas(14, 8)
    a = c.input_cell(2, 0)
    if clip_side == "W":
        ins, out = c.box(6, 3, ins=1, out="W")
        left, right = out, ins[0]
    else:
        ins, out = c.box(6, 3, ins=1, out="E", clip=clip_side == "E")
        left, right = ins[0], out
    c.wire(a, (2, 3), left)
    c.wire(right, (11, 3))
    c.lamp(11, 3)
    return c.save(tmp_path / f"one-{clip_side}.png")


def test_a_one_input_box_is_oriented_by_its_cut_corners(tmp_path):
    east = ls.extract(_one_input(tmp_path, "E"))
    assert east.netlist.gates[0].ins == ("in0",) and east.netlist.outputs == ("g0",)
    assert east.input_at[0][0] < east.gate_boxes[0][0] < east.output_at[0][0]     # cell -> box -> lamp
    west = ls.extract(_one_input(tmp_path, "W"))                                 # same wiring, corners cut on the left
    assert west.netlist.gates[0].ins == ("in0",) and west.netlist.outputs == ("g0",)
    assert west.output_at[0][0] < west.gate_boxes[0][0] < west.input_at[0][0]     # the lamp side now feeds the box
    with pytest.raises(ls.SchematicError, match=r"1 of 1 component boxes have no readable input and output side "
                                                r"\(first: g0 at \(96,48\): pins E:1, W:1\)") as e:
        ls.extract(_one_input(tmp_path, None))
    assert not isinstance(e.value, ls.NotSchematic)


def test_a_one_input_box_drawn_downward_or_upward_is_oriented_the_same_way(tmp_path):
    down = dr.Canvas(11, 13)                                      # cell, box with its corners cut at the bottom, lamp
    ins, out = down.box(4, 3, ins=1, out="S")
    down.wire(down.input_cell(4, 0), ins[0])
    down.wire(out, (5, 10))
    down.lamp(5, 10)
    ex = ls.extract(down.save(tmp_path / "down.png"))
    assert ex.netlist.gates[0].ins == ("in0",) and ex.netlist.outputs == ("g0",)
    assert ex.input_at[0][1] < ex.gate_boxes[0][1] < ex.output_at[0][1]
    up = dr.Canvas(11, 13)                                        # the same column, corners cut at the top
    ins, out = up.box(4, 3, ins=1, out="N")
    up.wire(up.input_cell(4, 0), out)
    up.wire(ins[0], (4, 10))
    up.lamp(4, 10)
    ex = ls.extract(up.save(tmp_path / "up.png"))
    assert ex.netlist.gates[0].ins == ("in0",) and ex.netlist.outputs == ("g0",)
    assert ex.output_at[0][1] < ex.gate_boxes[0][1] < ex.input_at[0][1]           # the lamp's side feeds the box


def test_wires_too_thick_for_the_lattice_are_refused_by_name(tmp_path):
    path = dr.draw_netlist(_mini(), pitch=12, w=2).save(tmp_path / "coarse.png")
    with pytest.raises(ls.SchematicError, match="2px wires on a 12px lattice: too coarse") as e:
        ls.extract(path)
    assert not isinstance(e.value, ls.NotSchematic)
    det = ls.detect(path)                                         # a circuit, drawn with boxes, that was not read
    assert (det.is_schematic, det.supported, det.editor, det.gates) == (True, False, "box-and-wire", 0)
    assert "too coarse to tell a crossing from a junction" in det.reason


def test_the_soft_edge_of_a_symbol_is_never_ink():
    import numpy as np
    c = dr.Canvas(9, 6, pitch=32, w=2)                            # a white '?' with anti-aliased grey edges
    c.box(3, 2)
    a = np.asarray(c.im)
    inside = a[2 * 32:4 * 32, 3 * 32:6 * 32].reshape(-1, 3)
    greys = [tuple(px) for px in inside if tuple(px) not in (c.bg, c.sym)]
    assert len(greys) > 20                                        # the fixture really has blended pixels
    bg, ink, sym = ls._palette(a)
    assert (tuple(bg), tuple(ink), tuple(sym)) == (c.bg, c.ink, c.sym)
    ink_m, sym_m = ls._masks(a, bg, ink, sym)
    box = (slice(2 * 32 + 6, 4 * 32 - 6), slice(3 * 32 + 6, 6 * 32 - 6))          # clear of the outline and corners
    assert not ink_m[box].any() and sym_m[box].sum() >= 20
    assert ink_m[2 * 32 - 2:2 * 32, 4 * 32:5 * 32].all()          # the outline itself is ink


def test_stacked_boxes_share_a_border_and_touching_lamps_in_a_row_read_left_to_right(tmp_path):
    c = dr.Canvas(15, 13)
    cells = [c.input_cell(k, 0) for k in (1, 2, 3, 4)]
    up_in, up_out = c.box(6, 3)
    low_in, low_out = c.box(6, 5)                                 # directly below: one shared outline
    for start, pin in zip(cells, up_in + low_in):
        c.wire(start, (start[0], pin[1]), pin)
    c.wire(up_out, (11, 3), (11, 10))
    c.wire(low_out, (10, 5), (10, 10))
    c.lamp(10, 10)
    c.lamp(11, 10)                                                # the two discs touch
    ex = ls.extract(c.save(tmp_path / "stack.png"))
    nl = ex.netlist
    assert [(g.id, g.ins) for g in nl.gates] == [("g0", ("in0", "in1")), ("g1", ("in2", "in3"))]
    assert nl.outputs == ("g1", "g0") and ex.stats["crossings"] == 6
    heights = sorted(y1 - y0 for _, y0, _, y1 in ex.gate_boxes)
    assert heights == [31, 32]                                    # the shared outline costs one box a pixel row


def test_labels_and_a_labelled_wire_loop_are_not_components(tmp_path):
    circ = _mini()
    c = dr.draw_netlist(circ, pitch=16, w=1)
    # a closed wire loop (touching nothing) around a label, and a free label with its marker square
    assert (c.cols, c.rows) == (22, 34)
    c.wire((1, 29), (5, 29), (5, 32), (1, 32), (1, 29))
    c.d.text((3 * 16 + 8, 31 * 16), "AB", fill=c.sym, anchor="mm")
    c.label(7, 33, "note")
    ex = ls.extract(c.save(tmp_path / "loop.png"))
    assert ex.stats["rejected_boxes"] == 1                        # the loop's inside looked like a box with a symbol
    assert _canon(ex.netlist) == _canon(_netlist(circ)) and len(ex.gate_boxes) == 6


def test_a_pin_wired_to_nothing_is_a_floating_net_held_at_zero_and_reported(tmp_path):
    (tmp_path / "files").mkdir()
    c = dr.Canvas(14, 8)
    a = c.input_cell(2, 0)
    ins, out = c.box(6, 3)
    c.wire(a, (2, 3), ins[0])                                     # the second input pin is left unwired
    c.wire(out, (11, 3))
    c.lamp(11, 3)
    ex = ls.extract(c.save(tmp_path / "files" / "float.png"))
    assert ex.netlist.gates[0].ins == ("in0", "nc0") and ex.netlist.floating == ("nc0",)
    assert ex.issues == ("1 net(s) with no driver and no input device are held at 0 (nc0)",)
    assert ls.simulate(ex.netlist, {"in0": 1}, "or")["g0"] == 1 and ls.simulate(ex.netlist, {"in0": 1}, "and")["g0"] == 0
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")       # the engine passes the caveat on
    assert "files/float.png: 1 net(s) with no driver and no input device are held at 0 (nc0)" in res.notes


def test_a_circuit_with_no_lamp_has_no_output_and_says_so(tmp_path):
    c = dr.Canvas(14, 8)
    a, b = c.input_cell(2, 0), c.input_cell(3, 0)
    ins, _ = c.box(6, 3)                                          # the output pin's stub goes nowhere
    c.wire(a, (2, 3), ins[0])
    c.wire(b, (3, 4), ins[1])
    ex = ls.extract(c.save(tmp_path / "mute.png"))
    assert ex.netlist.outputs == () and ex.netlist.gates[0].ins == ("in0", "in1")
    assert ex.issues == ("no output device found: no wire from a gate output ends on a lamp or a free end",)
    assert "0 output device(s): a byte readout needs 1 to 8" in ls.sweep(ex.netlist, [BRAND]).notes[0]


def test_two_gate_outputs_on_one_net_fail_loudly(tmp_path):
    c = dr.Canvas(15, 13)
    a = c.input_cell(2, 0)
    up_in, up_out = c.box(6, 3)
    low_in, low_out = c.box(6, 7)
    c.wire(a, (2, 8))
    for pin in up_in + low_in:
        c.wire((2, pin[1]), pin)
        c.junction(2, pin[1])
    c.wire(up_out, (11, 3), (11, 7), low_out)
    with pytest.raises(ls.SchematicError, match=r"1 net\(s\) are driven by more than one gate output \(first: g0, g1\)"):
        ls.extract(c.save(tmp_path / "short.png"))


def _noise(path, seed=7):
    rng = random.Random(seed)
    Image.frombytes("RGB", (160, 120), bytes(rng.randrange(256) for _ in range(160 * 120 * 3))).save(path)
    return path


def _blocks(path, seed=3):
    """A code-like image: 8px black and white modules, most of them black."""
    rng = random.Random(seed)
    im = Image.new("RGB", (240, 240), (0, 0, 0))
    px = im.load()
    for by in range(30):
        for bx in range(30):
            if rng.random() < 0.35:
                for y in range(8):
                    for x in range(8):
                        px[bx * 8 + x, by * 8 + y] = (255, 255, 255)
    im.save(path)
    return path


def _table(path):
    """A ruled table with a word in every cell: boxes and straight lines, but no wires and no grid."""
    c = dr.Canvas(20, 12, pitch=16, w=1, theme="light", dots=False)
    for j in range(1, 11, 2):
        for i in range(1, 19, 3):
            c.outline(i, j, 3, 2)
            c.d.text((i * 16 + 24, j * 16 + 16), "ab", fill=c.ink, anchor="mm")
    return c.save(path)


def _plain_lines(path):
    """Straight lines and nothing else: no boxes, no grid dots."""
    c = dr.Canvas(20, 14, dots=False)
    c.wire((2, 2), (12, 2), (12, 9), (5, 9))
    c.wire((8, 4), (8, 12), (17, 12))
    return c.save(path)


def _canvas_without_boxes(path):
    """An editor canvas (dot grid, wires, a junction, a lamp) whose components are not boxes."""
    c = dr.Canvas(20, 14)
    c.wire((2, 2), (12, 2), (12, 9), (5, 9))
    c.wire((8, 2), (8, 6), (16, 6))
    c.junction(8, 2)
    c.lamp(16, 6)
    c.d.polygon([(5 * 16, 9 * 16 - 12), (5 * 16, 9 * 16 + 28), (3 * 16, 9 * 16 + 8)], outline=c.ink)   # a shaped gate
    return c.save(path)


def _blank(path):
    """One flat colour: a placeholder image, a redacted screenshot."""
    Image.new("RGB", (200, 150), (30, 30, 30)).save(path)
    return path


def _speck(path):
    """A flat page with one small mark on it."""
    im = Image.new("RGB", (100, 100), (255, 255, 255))
    ImageDraw.Draw(im).rectangle((40, 40, 44, 44), fill=(0, 0, 0))
    im.save(path)
    return path


def _text_page(path):
    """A screenshot of text: a flat background and thin strokes, few of them straight for long."""
    im = Image.new("RGB", (420, 200), (255, 255, 255))
    d = ImageDraw.Draw(im)
    for k, line in enumerate(["The quick brown fox jumps over", "a lazy dog and goes on to say", "sphinx of black quartz, judge",
                              "my vow: pack my box with five", "dozen liquor jugs, or so it goes"]):
        d.text((12, 14 + 34 * k), line, fill=(0, 0, 0), font=ImageFont.load_default(size=22))
    im.save(path)
    return path


def _digit_grid(path, cell=32, font=24, seed=1):
    """A sudoku-style grid: ruled cells (boxes on straight lines) with a digit in most of them. The
    digits leave small specks behind once their long strokes are taken away."""
    rng = random.Random(seed)
    margin, side = 10, 9 * cell + 21
    im = Image.new("RGB", (side, side), (255, 255, 255))
    d = ImageDraw.Draw(im)
    for k in range(10):
        t, o = (3 if k % 3 == 0 else 1), margin + k * cell
        d.rectangle((o, margin, o + t - 1, side - margin - 1), fill=(0, 0, 0))
        d.rectangle((margin, o, side - margin - 1, o + t - 1), fill=(0, 0, 0))
    for r in range(9):
        for c in range(9):
            if rng.random() < 0.75:
                d.text((margin + c * cell + cell // 2, margin + r * cell + cell // 2), str(rng.randrange(1, 10)),
                       fill=(0, 0, 0), font=ImageFont.load_default(size=font), anchor="mm")
    im.save(path)
    return path


def test_images_that_are_not_circuits_are_told_apart_by_name(tmp_path):
    for make, why in ((_noise, "no flat background"), (_blocks, "blocks, not line art"),
                      (_table, "and no editor grid"), (_plain_lines, "no component boxes and no editor grid"),
                      (_blank, "no line art on the background"), (_speck, "too little line art"),
                      (_text_page, r"only \d+% of the ink is straight horizontal or vertical line")):
        path = make(tmp_path / f"{make.__name__}.png")
        with pytest.raises(ls.NotSchematic, match=why) as e:
            ls.extract(path)
        det = ls.detect(path)
        assert (det.is_schematic, det.supported, det.gates) == (False, False, 0) and det.reason == str(e.value)
    (tmp_path / "text.png").write_bytes(b"not an image at all")
    with pytest.raises(ls.NotSchematic, match="not a readable PNG, GIF, BMP or WEBP image") as e:
        ls.extract(tmp_path / "text.png")
    assert "'text.png'" in str(e.value) and str(tmp_path) not in str(e.value)   # the file's name, not its whole path
    Image.new("RGB", (20, 20), (0, 0, 0)).save(tmp_path / "tiny.png")
    with pytest.raises(ls.NotSchematic, match="too small"):
        ls.extract(tmp_path / "tiny.png")


@pytest.mark.parametrize("cell, font, seed", [(32, 24, 1), (40, 20, 1), (24, 24, 1), (48, 24, 2)])
def test_a_grid_of_digits_is_not_a_circuit(tmp_path, cell, font, seed):
    path = _digit_grid(tmp_path / "digits.png", cell, font, seed)
    with pytest.raises(ls.NotSchematic, match="boxes and lines but no wire lattice found: .*, and no editor grid"):
        ls.extract(path)                                # the specks its digits leave are not an editor's dot grid
    (tmp_path / "files").mkdir()
    path.rename(tmp_path / "files" / "digits.png")
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "none" and "files/digits.png: not a circuit export" in res.notes


def test_a_circuit_canvas_without_boxes_is_a_circuit_that_cannot_be_read(tmp_path):
    path = _canvas_without_boxes(tmp_path / "shaped.png")
    with pytest.raises(ls.NoBoxes, match=r"a circuit canvas \(dot grid every 16px\) with no rectangular "
                                         r"component boxes: either its gates are drawn as distinctive shapes, "
                                         r"which are not vectorized, or this is a lossy, blurred or rescaled copy") as e:
        ls.extract(path)
    assert not isinstance(e.value, ls.NotSchematic)
    det = ls.detect(path)
    assert (det.is_schematic, det.supported, det.editor) == (True, False, "grid-canvas")


def _misfit(path, grid):
    """Wires on a 20px lattice and component boxes drawn half a cell off it, so no lattice fits both:
    a drawing this reader cannot read. `grid` is what lies under it:
      full    an editor's dot on every lattice point
      none    nothing
      sparse  a dot on a random seventh of the lattice points
      left    a dot on every lattice point of the left half
      top     a dot on every lattice point of the upper nine rows of twenty
      fine    a stipple at half the pitch: dots five wire widths apart
    """
    c = dr.Canvas(24, 20, pitch=20, w=2, dots=grid == "full")
    rng = random.Random(3)
    if grid == "sparse":
        for i in range(c.cols):
            for j in range(c.rows):
                if rng.random() < 1 / 7:
                    c._square(i, j, 2)
    elif grid in ("left", "top"):
        for i in range(12 if grid == "left" else c.cols):
            for j in range(c.rows if grid == "left" else 9):
                c._square(i, j, 2)
    elif grid == "fine":
        for x in range(4, c.cols * 20, 10):
            for y in range(4, c.rows * 20, 10):
                c._rect(x, y, x + 2, y + 2)
    for j in (1, 2, 3, 4, 15, 16, 17, 18) if grid == "fine" else (1, 18):   # the stipple needs more line than dot
        c.wire((1, j), (22, j))
    c.wire((1, 1), (1, 18))
    c.wire((22, 1), (22, 18))
    for i, j in ((4, 6), (15, 6), (4, 10), (15, 10)):
        x0, y0 = i * 20 + 10, j * 20 + 10
        c._rect(x0 - 2, y0 - 2, x0 + 62, y0 + 42)
        c._rect(x0, y0, x0 + 60, y0 + 40, fill=c.bg)
        c.d.text((x0 + 30, y0 + 20), "?", fill=c.sym, anchor="mm")
    return c.save(path)


def test_an_editor_canvas_whose_boxes_miss_the_lattice_is_a_circuit_that_cannot_be_read(tmp_path):
    path = _misfit(tmp_path / "full.png", "full")
    with pytest.raises(ls.SchematicError, match="no wire lattice found: wires do not run half a cell off the "
                                                "component outlines") as e:
        ls.extract(path)
    assert not isinstance(e.value, (ls.NotSchematic, ls.NoBoxes))  # the dot grid makes it a circuit, unread
    det = ls.detect(path)
    assert (det.is_schematic, det.supported, det.editor) == (True, False, "box-and-wire")
    (tmp_path / "files").mkdir()
    path.rename(tmp_path / "files" / "full.png")
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()
    assert "files/full.png: a circuit export that could not be read: no wire lattice found" in res.notes


@pytest.mark.parametrize("grid, rule", [("none", None), ("sparse", "DOT_MIN_COVER"), ("left", "DOT_MIN_SPAN"),
                                        ("top", "DOT_MIN_SPAN"), ("fine", "DOT_MIN_PITCH")])
def test_dots_that_are_not_an_editors_grid_do_not_make_a_drawing_a_circuit(tmp_path, monkeypatch, grid, rule):
    path = _misfit(tmp_path / f"{grid}.png", grid)
    with pytest.raises(ls.NotSchematic, match="boxes and lines but no wire lattice found: .*, and no editor grid"):
        ls.extract(path)
    assert ls.detect(path).is_schematic is False
    if rule:                      # and it is this rule that says so: without it the dots pass for a grid
        monkeypatch.setattr(ls, rule, 0)
        with pytest.raises(ls.SchematicError, match="no wire lattice found") as e:
            ls.extract(path)
        assert not isinstance(e.value, ls.NotSchematic)


def test_a_crop_that_cuts_wires_is_read_with_a_warning(tmp_path):
    circ = _mini()
    c = dr.draw_netlist(circ, pitch=16, w=1)
    whole = ls.extract(c.save(tmp_path / "whole.png"))
    assert whole.issues == () and len(whole.netlist.inputs) == 3 and len(whole.netlist.outputs) == 3
    # cut the lamps off: the three wires that ran to them now run off the right edge
    lamp_x = max(x for x, _ in whole.output_at)
    c.im.crop((0, 0, lamp_x - 20, c.im.height)).save(tmp_path / "right.png")
    right = ls.extract(tmp_path / "right.png")
    assert len(right.netlist.outputs) == 3                        # still read, as devices at the edge ...
    assert right.issues == ("3 wire(s) run off the edge of the image and were read as devices: the image may be "
                            "a crop of the export",)             # ... but the reader says what they are
    # cut the input cells off, a little past a row of the lattice: the three trunks run off the top edge
    c.im.crop((0, 2 * 16 + 5, c.im.width, c.im.height)).save(tmp_path / "top.png")
    top = ls.extract(tmp_path / "top.png")
    assert len(top.netlist.inputs) == 3 and top.issues == right.issues
    (tmp_path / "files").mkdir()
    (tmp_path / "top.png").rename(tmp_path / "files" / "top.png")
    assert "files/top.png: 3 wire(s) run off the edge of the image" in ls.solve(tmp_path, PROFILE, out=tmp_path / "o").notes
    # thick wires, cut two pixels short of half a cell from a lattice column: the cut ends round to
    # just outside the image, and every wire that crossed the cut is still counted
    big = dr.draw_netlist(circ, pitch=64, w=4)
    cut_col = 2 + len(circ.inputs) + len(circ.gates)              # the first column right of the trunks
    big.im.crop((cut_col * 64 + 2, 0, big.im.width, big.im.height)).save(tmp_path / "left.png")
    left = ls.extract(tmp_path / "left.png")
    crossing = sum(len(g.ins) for g in circ.gates) + len(circ.gates) + len(circ.outputs)   # pins, returns, lamps
    assert crossing == 22 and left.issues[-1].startswith("22 wire(s) run off the edge of the image")


def _png_header(path, width, height):
    """A PNG whose header claims width x height and whose pixel data is a few bytes: a file of under
    a hundred bytes that says it is huge."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(b"\0" * 16)) + chunk(b"IEND", b""))
    return path


def test_pillow_opens_only_the_formats_named_and_no_other_decoder(tmp_path, board):
    # Pillow picks a decoder by content, not by name. A JPEG named .png is not opened as a JPEG ...
    Image.open(board / "files" / "board.png").save(tmp_path / "photo.jpg", quality=60)
    (tmp_path / "photo.jpg").rename(tmp_path / "photo.png")
    assert Image.open(tmp_path / "photo.png").format == "JPEG"    # the fixture: Pillow itself would
    with pytest.raises(ls.NotSchematic, match=r"not a readable PNG, GIF, BMP or WEBP image \(UnidentifiedImageError"):
        ls.extract(tmp_path / "photo.png")
    # ... and an EPS named .png never reaches the EPS decoder, which would start Ghostscript on it
    (tmp_path / "page.png").write_bytes(b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n%%EndComments\n"
                                        b"newpath 10 10 moveto 90 90 lineto stroke\nshowpage\n%%EOF\n")
    assert Image.open(tmp_path / "page.png").format == "EPS"
    with pytest.raises(ls.NotSchematic, match=r"not a readable PNG, GIF, BMP or WEBP image \(UnidentifiedImageError"):
        ls.extract(tmp_path / "page.png")
    # the formats named are opened whatever the file is called
    Image.open(board / "files" / "board.png").save(tmp_path / "board.gif")
    (tmp_path / "board.gif").rename(tmp_path / "board.dat")
    assert len(ls.extract(tmp_path / "board.dat").netlist.gates) == 38


def test_an_image_over_the_pixel_cap_is_not_decoded_and_says_so(tmp_path, monkeypatch, board):
    monkeypatch.setattr(ls, "MAX_PIXELS", 100_000)
    with pytest.raises(ls.Unexamined, match=r"image is 976x\d+: over the 100000-pixel cap, not decoded"):
        ls.extract(board / "files" / "board.png")
    det = ls.detect(board / "files" / "board.png")
    assert (det.is_schematic, det.supported) == (False, False) and "over the 100000-pixel cap" in det.reason
    res = ls.solve(board, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()
    assert "files/board.png: not examined: image is 976x" in res.notes


def test_an_image_over_pillows_own_limit_is_unexamined_not_ruled_out(tmp_path):
    # Pillow refuses a header this large inside open(), before this engine's own cap is reached
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    huge = _png_header(chal / "files" / "huge.png", 20000, 20000)
    with pytest.raises(ls.Unexamined, match="over Pillow's pixel limit, not decoded"):
        ls.extract(huge)
    assert ls.detect(huge).is_schematic is False
    res = ls.solve(chal, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()             # it may be the circuit: not `none`
    assert "files/huge.png: not examined: over Pillow's pixel limit" in res.notes
    # a header between this engine's cap and Pillow's is refused by this engine, by its size
    with pytest.raises(ls.Unexamined, match=r"image is 9000x9000: over the 64000000-pixel cap, not decoded"):
        ls.extract(_png_header(tmp_path / "big.png", 9000, 9000))


def _not_root():
    if os.geteuid() == 0:        # root reads everything: the fixture cannot be made
        pytest.skip("not run: running as root, so a file cannot be made unreadable")


def test_a_truncated_or_damaged_image_is_unexamined_not_ruled_out(tmp_path, board, monkeypatch):
    """A cut-off PNG is a common handout. What it shows was never seen, so it is not `not a circuit`."""
    png = (board / "files" / "board.png").read_bytes()
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    cut = chal / "files" / "cut.png"
    cut.write_bytes(png[:len(png) * 2 // 3])                      # the header is whole, the pixel data is not
    with pytest.raises(ls.Unexamined, match=r"a PNG image whose pixel data is truncated or damaged, not decoded in "
                                            r"full \(OSError: .*truncated.*\): repair the file and run again"):
        ls.extract(cut)
    det = ls.detect(cut)
    assert (det.is_schematic, det.supported) == (False, False) and "truncated or damaged" in det.reason
    res = ls.solve(chal, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()             # it may be the circuit: not `none`
    assert "files/cut.png: not examined: a PNG image whose pixel data is truncated or damaged" in res.notes
    assert "not a circuit export" not in res.notes

    # an image signature in front of a header no decoder takes: a damaged image, not a non-image
    broken = chal / "files" / "broken"
    broken.write_bytes(png[:8] + b"\0" * 64)
    with pytest.raises(ls.Unexamined, match=r"starts as an image but its header is damaged, not decoded "
                                            r"\(UnidentifiedImageError: cannot identify image file 'broken'\)"):
        ls.extract(broken)
    # ... while a file that only has an image's name was looked at, and is not one
    (chal / "files" / "words.png").write_bytes(b"plain words under an image's name\n" * 4)
    with pytest.raises(ls.NotSchematic, match=r"not a readable PNG, GIF, BMP or WEBP image \(UnidentifiedImageError"):
        ls.extract(chal / "files" / "words.png")
    cut.unlink()
    broken.unlink()
    res = ls.solve(chal, PROFILE, out=tmp_path / "out")
    assert res.status == "none" and "files/words.png: not a circuit export (not a readable PNG" in res.notes

    # a decoder that fails in a way of its own while reading the header: unexamined as well
    def boom(*a, **k):
        raise ValueError("bad header field")
    monkeypatch.setattr(Image, "open", boom)
    with pytest.raises(ls.Unexamined, match=r"the image header could not be read \(ValueError: bad header field\)"):
        ls.extract(board / "files" / "board.png")


def test_an_image_that_cannot_be_read_is_unexamined_not_ruled_out(tmp_path, board):
    _not_root()
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    locked = chal / "files" / "locked.png"
    locked.write_bytes((board / "files" / "board.png").read_bytes())
    plain = chal / "files" / "sealed"                             # no image extension, and no first bytes to go by
    plain.write_bytes(b"words")
    locked.chmod(0)
    plain.chmod(0)
    try:
        with pytest.raises(ls.Unexamined, match=r"the file could not be read \(PermissionError: .*'locked.png'\)"):
            ls.extract(locked)
        res = ls.solve(chal, PROFILE, out=tmp_path / "out")
    finally:
        locked.chmod(0o644)
        plain.chmod(0o644)
    assert res.status == "unsure" and res.flags == ()
    assert "files/locked.png: not examined: the file could not be read (PermissionError" in res.notes
    assert "files/sealed: not examined: the file could not be read (PermissionError" in res.notes
    assert str(tmp_path) not in res.notes                         # named by its place in the challenge, not by a full path
    res = ls.solve(chal, PROFILE, out=tmp_path / "out")           # readable again: the circuit is read
    assert f"{BODY!r} <- every gate nor" in res.notes and "not examined" not in res.notes


# ========================================================================================== engine

def test_solve_reports_a_body_only_reading_as_unsure_text_never_as_a_flag(board, tmp_path, transducer):
    res = ls.solve(board, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == () and res.engine == "toolkits.logic_schematic"
    # the reading is there for the agent, with how it was read ...
    assert f"{BODY!r} <- every gate nor, text {BRAND!r}, selectors in0,in1 at 01 10 11" in res.notes
    assert res.evidence[0].kind == "match" and res.evidence[0].path == "files/board.png"
    assert "logigator-like export, 16px lattice: 38 gates, 10 input devices (9 independent), 8 outputs" in res.evidence[0].detail
    assert res.evidence[1].kind == "decode" and res.evidence[1].detail.startswith(repr(BODY))
    # ... but nothing in what the engine prints is in the event flag format: intake scans an engine's
    # output for flags when its result names none, and an inferred reading must not become a found flag
    assert FF.find_flags(res.to_json()) == []
    wrote = json.loads((tmp_path / "out" / "netlist.json").read_text())
    assert _canon(ls.Netlist.from_dict(wrote)) == _canon(transducer)
    first = json.loads((tmp_path / "out" / "readings.json").read_text())[0]
    assert first == {"stream": BODY, "text": BRAND, "kinds": {"0": "nor"}, "selectors": ["in0", "in1"],
                     "data": ["in2", "in4", "in5", "in6", "in7", "in8", "in9"], "states": ["01", "10", "11"],
                     "msb_first": True, "out_msb_first": True, "flags": []}
    assert f"written: {tmp_path / 'out' / 'netlist.json'}, {tmp_path / 'out' / 'readings.json'}" in res.notes
    # the evidence holds the best MAX_READINGS readings, in order, and says where the others are
    every = json.loads((tmp_path / "out" / "readings.json").read_text())
    decodes = [e.detail for e in res.evidence if e.kind == "decode"]
    assert len(every) > ls.MAX_READINGS and len(decodes) == ls.MAX_READINGS
    assert [d.split(" <- ")[0] for d in decodes] == [repr(r["stream"]) for r in every[:ls.MAX_READINGS]]
    assert f"{len(every) - ls.MAX_READINGS} more printable reading(s) are in readings.json only" in res.notes


def test_a_result_with_no_flags_never_prints_text_in_the_event_flag_format(tmp_path):
    """Intake scans an engine's output for the flag format when its result names no flag. A reading
    that holds an unclosed `PREFIX{` is closed by the next brace in the printed JSON, its own closing
    one included, when the event's flag body may hold spaces: an inferred value would become a found
    flag. So the braces of such a result are escaped."""
    spaced = _profile(body=SPACED_BODY)
    ff = flagfmt.for_profile(spaced)
    chal = tmp_path / "chal"
    chal.mkdir()
    open_flag = f"{spaced.flag.prefixes[0]}{{"                    # five characters: one per character of the brand
    (chal / "open.json").write_text(json.dumps(_netlist(_pla([(BRAND, open_flag)], states=((0, 1),))).to_dict()))
    res = ls.solve(chal, spaced, netlist="open.json", kinds="nor", out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()
    assert ff.find_flags(res.to_json()) == []                     # what intake would scan
    # the reading is still reported, with its braces spelled out, and the result says so
    decode = next(e for e in res.evidence if e.kind == "decode")
    assert decode.detail.startswith(f"'{open_flag[:-1]}\\x7b' <- every gate nor, text {BRAND!r}")
    assert "{" not in res.notes and "}" not in res.notes and f"{open_flag[:-1]}\\x7b" in res.notes
    assert "braces are written \\x7b and \\x7d in this result" in res.notes
    # the file for the agent keeps the stream as it was read
    assert json.loads((tmp_path / "out" / "readings.json").read_text())[0]["stream"] == open_flag
    # the fixture is the dangerous case: left as it was, the printed result would hold a "flag"
    raw = ls._solve(chal, spaced, {"netlist": "open.json", "kinds": "nor", "out": tmp_path / "out"})
    assert raw.status == "unsure" and raw.flags == () and len(ff.find_flags(raw.to_json())) == 1

    # where the format cannot match, nothing is rewritten: the same circuit under a body with no spaces
    plain = ls.solve(chal, PROFILE, netlist="open.json", kinds="nor", out=tmp_path / "out2")
    assert FF.find_flags(plain.to_json()) == [] and f"'{open_flag}' <- every gate nor" in plain.notes
    assert "\\x7b" not in plain.notes

    # every result with no flags is covered, not only readings: a file name in a `none` note
    named = tmp_path / "named" / "files"
    named.mkdir(parents=True)
    _noise(named / f"{open_flag}scan.png")
    res = ls.solve(named.parent, spaced, out=tmp_path / "out3")
    assert res.status == "none" and ff.find_flags(res.to_json()) == []
    assert f"files/{open_flag[:-1]}\\x7bscan.png: not a circuit export" in res.notes
    raw = ls._solve(named.parent, spaced, {"out": tmp_path / "out3"})
    assert len(ff.find_flags(raw.to_json())) == 1
    # ... and the path of a piece of evidence: a readable circuit in a file named that way
    (named / f"{open_flag}scan.png").unlink()
    dr.draw_netlist(_mini()).save(named / f"{open_flag}mini.png")
    res = ls.solve(named.parent, spaced, out=tmp_path / "out5")
    assert res.status == "unsure" and ff.find_flags(res.to_json()) == []
    assert res.evidence[0].kind == "match" and res.evidence[0].path == f"files/{open_flag[:-1]}\\x7bmini.png"
    assert len(ff.find_flags(ls._solve(named.parent, spaced, {"out": tmp_path / "out5"}).to_json())) == 1

    # a result that carries flags is left alone: intake takes its flags and does not scan
    flag = f"{spaced.flag.prefixes[0]}{{n0r_g4t3s}}"
    (chal / "spells.json").write_text(json.dumps(_netlist(_pla([(BRAND, flag)])).to_dict()))
    res = ls.solve(chal, spaced, netlist="spells.json", kinds="nor", out=tmp_path / "out4")
    assert res.status == "candidate" and res.flags == (flag,)
    assert res.evidence[1].detail.startswith(f"{flag!r} <- every gate nor") and "\\x7b" not in res.notes


def test_solve_wraps_readings_only_when_asked_best_first(board, tmp_path):
    res = ls.solve(board, PROFILE, wrap=True, out=tmp_path / "out")
    prefix = PROFILE.flag.prefixes[0]
    assert res.status == "candidate" and res.flags[0] == f"{prefix}{{{BODY}}}"
    assert all(FF.is_flag(f) for f in res.flags) and len(res.flags) == len(set(res.flags)) <= ls.MAX_READINGS
    assert "wrapped in the flag format by request" in res.notes and "inferred, not proven" in res.notes
    every = json.loads((tmp_path / "out" / "readings.json").read_text())
    assert len(every) > ls.MAX_READINGS == len(res.flags)         # more readings than are returned, and it says so
    assert res.flags == tuple(f"{prefix}{{{r['stream']}}}" for r in every[:ls.MAX_READINGS])
    assert f"only the first {ls.MAX_READINGS} are returned; readings.json has the rest" in res.notes
    few = ls.solve(board, PROFILE, wrap=True, kinds="nor", max_hypotheses=1, out=tmp_path / "out1")
    assert few.flags == res.flags[:1] and "are returned" not in few.notes
    # a reading the flag format cannot hold (a brace in the body) is never wrapped into a non-flag
    (tmp_path / "brace.json").write_text(json.dumps(_netlist(_pla([(BRAND, "has}brace{insid")])).to_dict()))
    res = ls.solve(tmp_path, PROFILE, netlist="brace.json", wrap=True, out=tmp_path / "out3")
    assert res.evidence[1].detail.startswith("'has}brace{insid' <- every gate nor")          # read, and reported
    assert res.status == "candidate" and res.flags and all(FF.is_flag(f) for f in res.flags)
    assert not any("brace" in f for f in res.flags)
    assert "reading(s) cannot be a flag body in this event's format and were left unwrapped" in res.notes
    unknown = _profile(prefixes=())                               # a format not known yet: nothing to wrap into
    res = ls.solve(board, unknown, wrap=True, out=tmp_path / "out2")
    assert res.status == "unsure" and res.flags == ()
    assert "wrap was asked for but no reading fits the event flag format" in res.notes


def test_solve_returns_a_flag_the_circuit_itself_spells_as_a_candidate(tmp_path):
    flag = f"{PROFILE.flag.prefixes[0]}{{n0r_g4t3s}}"
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "mine.json").write_text(json.dumps(_netlist(_pla([(BRAND, flag)])).to_dict()))
    res = ls.solve(chal, PROFILE, netlist="mine.json", out=tmp_path / "out")
    assert res.status == "candidate" and res.flags == (flag,)                  # never `solved`: the kind is inferred
    assert res.evidence[0].path == "mine.json" and "netlist given by the operator" in res.evidence[0].detail
    assert "under an inferred gate kind and readout" in res.notes
    (chal / "bad.json").write_text('{"gates": [], "inputs": ["a"]}')
    res = ls.solve(chal, PROFILE, netlist="bad.json", out=tmp_path / "out")
    assert res.status == "blocked" and "netlist bad.json is not usable: netlist field 'outputs' must be a list" in res.notes
    res = ls.solve(chal, PROFILE, netlist="absent.json", out=tmp_path / "out")
    assert res.status == "blocked" and "netlist absent.json is not usable" in res.notes


def test_solve_statuses_for_no_circuit_an_unreadable_circuit_and_no_reading(tmp_path):
    none = tmp_path / "none" / "files"
    none.mkdir(parents=True)
    _noise(none / "photo.png")
    (none / "readme.txt").write_text("words")
    res = ls.solve(none.parent, PROFILE, out=tmp_path / "o1")
    assert res.status == "none" and res.flags == ()
    assert "files/photo.png: not a circuit export (no flat background" in res.notes
    assert not (tmp_path / "o1").exists()                         # nothing read, nothing written
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ls.solve(empty, PROFILE, out=tmp_path / "o2").notes == "no image file"

    shaped = tmp_path / "shaped" / "files"
    shaped.mkdir(parents=True)
    _canvas_without_boxes(shaped / "canvas.png")
    _noise(shaped / "photo.png")
    res = ls.solve(shaped.parent, PROFILE, out=tmp_path / "o3")
    assert res.status == "unsure" and res.flags == ()
    assert "files/canvas.png: a circuit export that could not be read: a circuit canvas" in res.notes

    quiet = tmp_path / "quiet" / "files"                          # a readable circuit with too few inputs to feed text
    quiet.mkdir(parents=True)
    dr.draw_netlist(_mini()).save(quiet / "mini.png")
    res = ls.solve(quiet.parent, PROFILE, out=tmp_path / "o4")
    assert res.status == "unsure" and res.flags == ()
    assert "a circuit was read but no gate kind and readout gives printable output" in res.notes
    assert "3 independent input(s): no split leaves 7 or 8 data lines" in res.notes
    assert (tmp_path / "o4" / "netlist.json").is_file()           # the netlist is still handed over

    assert "written: " in res.notes and "1-" not in res.notes     # one circuit: plain file names
    dr.draw_netlist(_mini(), theme="light").save(quiet / "second.png")
    res = ls.solve(quiet.parent, PROFILE, out=tmp_path / "o5")    # two circuits: both read, files numbered
    assert [e.path for e in res.evidence] == ["files/mini.png", "files/second.png"]
    assert sorted(p.name for p in (tmp_path / "o5").iterdir()) == [
        "1-mini.netlist.json", "1-mini.readings.json", "2-second.netlist.json", "2-second.readings.json"]

    with pytest.raises(ValueError, match="unknown option depth"):
        ls.solve(quiet.parent, PROFILE, depth=3)
    with pytest.raises(FileNotFoundError, match="no such challenge folder"):
        ls.solve(tmp_path / "absent", PROFILE)


def test_solve_options_narrow_the_kinds_and_add_texts(board, tmp_path):
    res = ls.solve(board, PROFILE, kinds="nand,xor", out=tmp_path / "o1")
    assert res.status == "unsure" and BODY not in res.notes       # NOR was not tried
    with pytest.raises(ValueError, match=r"logic_schematic: option kinds=\['nor', 'imp'\]: unknown gate kind 'imp' "
                                         r"\(known: nor, nand, and, or, xor, xnor\)"):
        ls.solve(board, PROFILE, kinds=["nor", "imp"], out=tmp_path / "o2")
    assert not (tmp_path / "o2").exists()                         # refused before anything was read
    res = ls.solve(board, PROFILE, texts=["Q"], max_hypotheses=1, out=tmp_path / "o3")
    assert f"{''.join(chr(ord('Q') ^ m) for m in MASKS)!r} <- every gate nor, text 'Q'" in res.notes
    assert "stopped at the cap of 1 hypotheses" in res.notes


@pytest.mark.parametrize("value, wraps", [(True, True), ("true", True), ("True", True), ("yes", True), (1, True),
                                          ("1", True), (" On ", True), (False, False), ("false", False),
                                          ("No", False), (0, False), ("off", False), (None, False)])
def test_the_wrap_option_takes_the_usual_spellings_of_true_and_false(board, tmp_path, value, wraps):
    res = ls.solve(board, PROFILE, wrap=value, kinds="nor", max_hypotheses=40, out=tmp_path / "out")
    assert (res.status, bool(res.flags)) == (("candidate", True) if wraps else ("unsure", False))


@pytest.mark.parametrize("value", ["maybe", "truee", 2, 1.0, ["true"]])
def test_a_wrap_option_that_is_not_true_or_false_is_refused_not_read_as_false(board, tmp_path, value):
    with pytest.raises(ValueError, match="logic_schematic: option wrap=.* is not true or false"):
        ls.solve(board, PROFILE, wrap=value, out=tmp_path / "out")
    assert not (tmp_path / "out").exists()                        # refused before anything was read


def test_an_operator_text_too_long_to_feed_is_named_not_dropped_silently(board, tmp_path):
    long = "L" + "o" * 70 + "ng"
    res = ls.solve(board, PROFILE, texts=[long, "Q"], kinds="nor", out=tmp_path / "out")
    assert f"1 text(s) given with `texts` are over {ls.MAX_TEXT} characters and were not fed (first: {long[:24]!r}...)" in res.notes
    assert " over 9 text(s)" in res.notes                         # Q and the eight profile texts were fed
    fits = ls.solve(board, PROFILE, texts=["x" * ls.MAX_TEXT], kinds="nor", max_hypotheses=4, out=tmp_path / "o2")
    assert "were not fed" not in fits.notes                       # exactly at the limit is fed
    # a text with a character the data lines cannot carry is fed where it fits, and the result says so
    res = ls.solve(board, PROFILE, texts=["Z\xc9TA+"], kinds="nor", out=tmp_path / "o3")
    assert ("files/board.png: 1 text(s) hold a character too wide for the data lines of a split and were not "
            "fed there (first: 'ZÉTA+' on 7 lines)") in res.notes


def test_a_circuit_that_spells_more_flags_than_are_returned_says_so(tmp_path):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789_-."
    texts = [chars[k:k + 3] for k in range(0, 39, 3)]
    flags = [f"{PROFILE.flag.prefixes[0]}{{f{k:02}}}" for k in range(13)]
    assert len(texts) == 13 == ls.MAX_READINGS + 1 and all(FF.is_flag(f) and len(f) == 9 for f in flags)
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "many.json").write_text(json.dumps(_netlist(_pla(list(zip(texts, flags)))).to_dict()))
    res = ls.solve(chal, PROFILE, netlist="many.json", texts=texts, kinds="nor", out=tmp_path / "out")
    assert res.status == "candidate" and res.flags == tuple(flags[:ls.MAX_READINGS])       # best (first text) first
    assert res.notes.startswith("13 flag(s) in the event format read off the circuit under an inferred gate kind "
                                f"and readout; only the first {ls.MAX_READINGS} are returned; readings.json has the rest")
    streams = [r["stream"] for r in json.loads((tmp_path / "out" / "readings.json").read_text())]
    assert streams[:13] == flags
    (chal / "few.json").write_text(json.dumps(_netlist(_pla(list(zip(texts[:12], flags[:12])))).to_dict()))
    res = ls.solve(chal, PROFILE, netlist="few.json", texts=texts, kinds="nor", out=tmp_path / "out2")
    assert res.flags == tuple(flags[:12]) and "are returned" not in res.notes              # exactly the cap: no note


def test_readings_of_two_circuits_are_ranked_together(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    # a.png reads printable only for the second text given, b.png only for the first
    dr.draw_netlist(_pla([("W", "xyz")])).save(files / "a.png")
    dr.draw_netlist(_pla([("Q", "abc")])).save(files / "b.png")
    res = ls.solve(tmp_path, PROFILE, texts=["Q", "W"], kinds="nor", out=tmp_path / "out")
    assert [e.path for e in res.evidence if e.kind == "match"] == ["files/a.png", "files/b.png"]
    decodes = [(e.path, e.detail.split(" <- ")[0]) for e in res.evidence if e.kind == "decode"]
    assert decodes.index(("files/b.png", "'abc'")) == 0           # the better reading leads, whichever file it is in
    assert decodes.index(("files/a.png", "'xyz'")) > 0
    order = [path for path, _ in decodes]
    assert order == sorted(order, reverse=True)                   # every reading of b.png (text Q) before a.png's (text W)
    assert res.status == "unsure" and "best first: 'abc' <- every gate nor, text 'Q'" in res.notes


def test_challenge_images_prefers_the_sweeps_copy_and_skips_recon_and_links(tmp_path):
    names = lambda paths: [p.relative_to(tmp_path).as_posix() for p in paths]
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.png").write_bytes(b"x")
    (tmp_path / "files" / "b.txt").write_bytes(b"x")
    images, left_out = ls.challenge_images(tmp_path)
    assert names(images) == ["files/a.png"] and left_out == []
    (tmp_path / "unpacked" / "deep" / "recon").mkdir(parents=True)
    (tmp_path / "unpacked" / "deep" / "c.GIF").write_bytes(b"x")
    (tmp_path / "unpacked" / "deep" / "recon" / "old.png").write_bytes(b"x")
    (tmp_path / "unpacked" / "link.png").symlink_to(tmp_path / "files" / "a.png")
    assert names(ls.challenge_images(tmp_path)[0]) == ["unpacked/deep/c.GIF"]
    assert ls._scan(tmp_path)[1:] == ([], [])                     # a link is left out, not reported as a special file
    for k in range(ls.MAX_IMAGES + 3):
        (tmp_path / "unpacked" / f"n{k:02}.bmp").write_bytes(b"x")
    images, left_out = ls.challenge_images(tmp_path)              # sorted by path; the cap's overflow is handed back
    assert names(images) == ["unpacked/deep/c.GIF"] + [f"unpacked/n{k:02}.bmp" for k in range(ls.MAX_IMAGES - 1)]
    assert names(left_out) == [f"unpacked/n{k:02}.bmp" for k in range(ls.MAX_IMAGES - 1, ls.MAX_IMAGES + 3)]


def test_an_image_is_found_by_its_first_bytes_whatever_it_is_called(tmp_path, board):
    files = tmp_path / "files"
    files.mkdir()
    png = (board / "files" / "board.png").read_bytes()
    (files / "schematic").write_bytes(png)                        # no extension
    (files / "notes.txt").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 20)    # a PNG signature under a wrong name
    (files / "anim").write_bytes(b"GIF89a" + b"\0" * 20)
    (files / "old").write_bytes(b"GIF87a" + b"\0" * 20)
    (files / "pic").write_bytes(b"RIFF\x10\0\0\0WEBPVP8 " + b"\0" * 8)
    (files / "bitmap").write_bytes(b"BM" + b"\x46\0\0\0" + b"\0\0\0\0" + b"\x36\0\0\0" + b"\0" * 8)
    for name, data in (("readme", b"plain words, no image"), ("riff.wav", b"RIFF\x10\0\0\0WAVEfmt "),
                       ("bm-words", b"BMW owners manual"), ("short", b"BM"), ("empty", b""),
                       ("png-ish", b"\x89PNG but not the whole signature")):
        (files / name).write_bytes(data)
    images, left_out = ls.challenge_images(tmp_path)
    assert [p.name for p in images] == ["anim", "bitmap", "notes.txt", "old", "pic", "schematic"] and left_out == []
    def no_readme(path, *a, **k):                      # a file that cannot be read is listed, so that it is named later
        if Path(path).name == "readme":
            raise PermissionError(13, "Permission denied")
        return open(path, *a, **k)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ls, "open", no_readme, raising=False)
        assert [p.name for p in ls.challenge_images(tmp_path)[0]] == ["anim", "bitmap", "notes.txt", "old", "pic",
                                                                       "readme", "schematic"]
    for name in ("anim", "old", "pic", "bitmap", "notes.txt"):
        (files / name).unlink()
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")       # the extensionless board is read
    assert res.status == "unsure" and res.evidence[0].path == "files/schematic"
    assert f"{BODY!r} <- every gate nor, text {BRAND!r}" in res.notes


def test_images_over_the_cap_are_named_and_the_answer_is_not_none(tmp_path, board, monkeypatch):
    files = tmp_path / "files"
    files.mkdir()
    for k in range(ls.MAX_IMAGES):
        _noise(files / f"noise{k}.png", seed=k)
    (files / "zboard.png").write_bytes((board / "files" / "board.png").read_bytes())      # sorts last: over the cap
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()             # the circuit may be among those not looked at
    assert f"1 image(s) not examined, over the cap of {ls.MAX_IMAGES} per challenge: files/zboard.png" in res.notes
    for k in range(ls.MAX_IMAGES):                                # and every image that was looked at is accounted for
        assert f"files/noise{k}.png: not a circuit export (no flat background" in res.notes
    assert not (tmp_path / "out").exists()
    (files / "zboard.png").unlink()                               # the same eight alone: a clean `none`
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "none" and "not examined" not in res.notes
    assert res.notes.count("not a circuit export") == ls.MAX_IMAGES
    # many left out: the first MAX_IMAGES of them are named and the rest are counted
    monkeypatch.setattr(ls, "MAX_IMAGES", 2)
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure"
    left_out = ("6 image(s) not examined, over the cap of 2 per challenge: files/noise2.png, files/noise3.png "
                "and 4 more")
    assert left_out in res.notes
    # a circuit among the images that were looked at does not hide the ones that were not
    (files / "noise0.png").unlink()
    (files / "aboard.png").write_bytes((board / "files" / "board.png").read_bytes())
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")       # aboard and noise1 are looked at: the same six are not
    assert res.status == "unsure" and f"{BODY!r} <- every gate nor" in res.notes and left_out in res.notes
    res = ls.solve(tmp_path, PROFILE, wrap=True, out=tmp_path / "out")
    assert res.status == "candidate" and left_out in res.notes
    res = ls.solve(tmp_path, PROFILE, max_hypotheses=0, out=tmp_path / "out")
    assert res.status == "unsure" and "no gate kind and readout gives printable output" in res.notes
    assert left_out in res.notes
    # ... nor does a circuit that spells a flag: the candidate still names what was not looked at
    flag = f"{PROFILE.flag.prefixes[0]}{{n0r_g4t3s}}"
    (files / "aboard.png").unlink()
    dr.draw_netlist(_pla([(BRAND, flag)])).save(files / "aboard.png")
    res = ls.solve(tmp_path, PROFILE, kinds="nor", out=tmp_path / "out")
    assert res.status == "candidate" and res.flags == (flag,)
    assert res.notes.startswith("1 flag(s) in the event format read off the circuit under an inferred gate kind "
                                f"and readout; {left_out}; ")


def test_the_netlist_is_on_disk_before_the_sweep_starts(board, tmp_path, monkeypatch):
    seen = {}

    class Killed(Exception):
        pass

    def killed(nl, texts, **kw):                                  # a sweep that never comes back
        seen["netlist"] = json.loads((tmp_path / "out" / "netlist.json").read_text())
        raise Killed
    monkeypatch.setattr(ls, "sweep", killed)
    with pytest.raises(Killed):
        ls.solve(board, PROFILE, out=tmp_path / "out")
    assert len(seen["netlist"]["gates"]) == 38 and (tmp_path / "out" / "netlist.json").is_file()
    assert not (tmp_path / "out" / "readings.json").exists()


def _step_clock(monkeypatch):
    """Replace the engine's CPU clock with one that advances a second each time it is read."""
    ticks = iter(range(10_000))
    monkeypatch.setattr(ls, "_cpu", lambda: float(next(ticks)))


def test_the_cpu_budget_stops_the_engine_between_images_and_inside_the_sweep(tmp_path, monkeypatch):
    files = tmp_path / "files"
    files.mkdir()
    dr.draw_netlist(dr.nor_transducer(MASKS)).save(files / "first.png")
    _noise(files / "second.png")
    _noise(files / "third.png")
    # the clock reads 0 at the start and 1, 2, ... at each later look: a budget of 1.5 s lets the first
    # image through, stops before the second, and stops the first circuit's sweep before it starts
    _step_clock(monkeypatch)
    res = ls.solve(tmp_path, PROFILE, seconds=1.5, out=tmp_path / "out")
    assert res.status == "unsure" and res.flags == ()
    assert ("2 image(s) not examined, the budget of 1.5s CPU ran out (option seconds): files/second.png, "
            "files/third.png") in res.notes
    assert "files/first.png: stopped by the time budget after 0 hypotheses" in res.notes
    assert "files/first.png: 0 readout hypotheses" in res.notes and "second.png: not a circuit" not in res.notes
    assert len(json.loads((tmp_path / "out" / "netlist.json").read_text())["gates"]) == 38   # the netlist is kept
    # a budget that lasts: every image is looked at and the sweep runs to its end
    _step_clock(monkeypatch)
    res = ls.solve(tmp_path, PROFILE, seconds=9_999, out=tmp_path / "out")
    assert "not examined" not in res.notes and "time budget" not in res.notes
    assert "files/second.png: not a circuit export" in res.notes and f"{BODY!r} <- every gate nor" in res.notes
    # the sweep is stopped part-way: the clock is read once per image, then once before each hypothesis
    _step_clock(monkeypatch)
    res = ls.solve(tmp_path, PROFILE, seconds=9.5, out=tmp_path / "out")
    assert "files/first.png: stopped by the time budget after 6 hypotheses" in res.notes
    for bad in (0, -1):
        with pytest.raises(ValueError, match="option seconds=.* must be more than 0"):
            ls.solve(tmp_path, PROFILE, seconds=bad, out=tmp_path / "out")


class _OpenedAPipe(BaseException):
    """Raised by the tripwire below. Not an Exception, so nothing in the engine can swallow it."""


def _pipe_tripwire(monkeypatch):
    """Opening a named pipe for reading waits for a writer that never comes. So that an engine that
    does open one fails the test instead of hanging it, every open() of a pipe raises."""
    real_open = builtins.open

    def guarded(file, *a, **k):
        if isinstance(file, (str, os.PathLike)) and os.path.exists(file) and stat.S_ISFIFO(os.stat(file).st_mode):
            raise _OpenedAPipe(str(file))
        return real_open(file, *a, **k)
    monkeypatch.setattr(builtins, "open", guarded)


def test_a_named_pipe_in_the_challenge_folder_is_named_and_never_opened(tmp_path, board, monkeypatch):
    files = tmp_path / "files"
    (files / "sub").mkdir(parents=True)
    os.mkfifo(files / "pipe.png")                                 # an image's name
    os.mkfifo(files / "sub" / "apipe")                            # no extension: found by first bytes, if it were read
    _pipe_tripwire(monkeypatch)
    with pytest.raises(_OpenedAPipe):                             # the tripwire works: a plain open() would have hung
        open(files / "pipe.png", "rb")
    images, special, closed = ls._scan(tmp_path)
    assert (images, closed) == ([], [])
    assert special == [(files / "pipe.png", "a named pipe"), (files / "sub" / "apipe", "a named pipe")]
    assert ls.challenge_images(tmp_path) == ([], [])
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "none" and res.flags == ()               # a pipe is never the circuit
    assert res.notes == "2 special file(s) not opened: files/pipe.png (a named pipe), files/sub/apipe (a named pipe)"
    # beside a circuit: the circuit is read and the pipes are still named
    (files / "board.png").write_bytes((board / "files" / "board.png").read_bytes())
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert res.status == "unsure" and f"{BODY!r} <- every gate nor" in res.notes
    assert "2 special file(s) not opened: files/pipe.png (a named pipe), files/sub/apipe (a named pipe)" in res.notes
    # many of them: the first MAX_IMAGES are named and the rest are counted
    monkeypatch.setattr(ls, "MAX_IMAGES", 1)
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    assert "2 special file(s) not opened: files/pipe.png (a named pipe) and 1 more;" in res.notes
    # what the other kinds of special file are called
    assert [ls._special(m) for m in (stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK, 0)] == [
        "a named pipe", "a socket", "a device", "a device", "not a regular file"]


def test_a_folder_that_cannot_be_listed_is_named_and_the_rest_is_still_read(tmp_path, board):
    _not_root()
    files = tmp_path / "files"
    (files / "closed").mkdir(parents=True)
    (files / "dim").mkdir()
    png = (board / "files" / "board.png").read_bytes()
    (files / "closed" / "board.png").write_bytes(png)
    (files / "dim" / "board.png").write_bytes(png)
    _noise(files / "photo.png")
    (files / "closed").chmod(0)                                   # cannot be listed
    (files / "dim").chmod(0o400)                                  # can be listed; what is in it cannot be looked at
    try:
        images, special, closed = ls._scan(tmp_path)
        res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
        (files / "zboard.png").write_bytes(png)
        beside = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    finally:
        (files / "closed").chmod(0o755)
        (files / "dim").chmod(0o755)
    assert images == [files / "photo.png"] and special == []
    assert closed == [(files / "closed", "the folder could not be listed (Permission denied)"),
                      (files / "dim" / "board.png", "the entry could not be inspected (Permission denied)")]
    # the circuit may be in there: `unsure`, each named, and the image that could be read was read
    assert res.status == "unsure" and res.flags == ()
    assert res.notes.startswith(
        "files/closed: not examined: the folder could not be listed (Permission denied); "
        "files/dim/board.png: not examined: the entry could not be inspected (Permission denied); "
        "files/photo.png: not a circuit export (no flat background")
    # a circuit beside them is read, and they are still named
    assert beside.status == "unsure" and f"{BODY!r} <- every gate nor" in beside.notes
    assert "files/closed: not examined: the folder could not be listed (Permission denied)" in beside.notes
    assert "files/dim/board.png: not examined: the entry could not be inspected" in beside.notes


def test_readings_json_holds_every_printable_reading_however_many(tmp_path):
    # seven buffers and an inverter on the lowest lamp, every kind drawn: each text reads as itself
    # with the lowest bit of every character flipped, so 306 texts give at least 306 distinct readings
    devs = tuple(f"in{k}" for k in range(8))                      # in0 = bit 7 ... in7 = bit 0
    gates = [ls.Gate(f"b{k}", (devs[k], devs[k]), "and") for k in range(7)] + [ls.Gate("low", ("in7", "in7"), "nor")]
    nl = ls.Netlist(tuple(gates), devs, tuple(g.id for g in gates))
    texts = ["".join(p) for p in itertools.permutations("abcdefghijklmnopqr", 2)]
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "flip.json").write_text(json.dumps(nl.to_dict()))
    res = ls.solve(chal, PROFILE, netlist="flip.json", texts=texts, out=tmp_path / "out")
    every = [r["stream"] for r in json.loads((tmp_path / "out" / "readings.json").read_text())]
    assert len(texts) == 306 and len(every) >= 306 and len(set(every)) == len(every)
    # the reading of the last text fed is far past the first 200, and it is in the file
    last = "".join(chr(ord(c) ^ 1) for c in texts[-1])
    assert last == "sp" and every.index(last) >= 300
    for text in texts:
        assert "".join(chr(ord(c) ^ 1) for c in text) in every, text
    # the file is the whole sweep, in its order, and the count in the result is the file's
    sw = ls.sweep(nl, ls.event_texts(PROFILE, texts), flag_format=FF)
    assert every == [r.stream for r in sw.readings]
    assert res.status == "unsure" and f"{len(every)} printable" in res.notes
    assert f"{len(every) - ls.MAX_READINGS} more printable reading(s) are in readings.json only" in res.notes


def test_a_file_that_cannot_be_written_is_named_and_never_pointed_at(board, tmp_path):
    (tmp_path / "taken").write_text("a file where the folder should go")
    out = tmp_path / "taken" / "out"
    res = ls.solve(board, PROFILE, out=out)
    assert res.status == "unsure" and f"{BODY!r} <- every gate nor, text {BRAND!r}" in res.notes   # the reading is not lost
    assert f"could not write {out / 'netlist.json'}: Not a directory" in res.notes
    assert f"could not write {out / 'readings.json'}: Not a directory" in res.notes
    assert not any(n.startswith("written: ") for n in res.notes.split("; ")) and "in readings.json only" not in res.notes
    ok = ls.solve(board, PROFILE, out=tmp_path / "ok")
    hidden = len(json.loads((tmp_path / "ok" / "readings.json").read_text())) - ls.MAX_READINGS
    gone = "the rest are not on disk: readings.json could not be written (option out names another folder)"
    assert hidden > 0 and f"{hidden} more printable reading(s) are not shown here; {gone}" in res.notes
    assert "could not write" not in ok.notes and "not on disk" not in ok.notes
    assert any(n.startswith("written: ") for n in ok.notes.split("; "))
    # the same on the wrap path: more flags than are returned, and no file that has the rest
    res = ls.solve(board, PROFILE, wrap=True, out=out)
    assert res.status == "candidate" and len(res.flags) == ls.MAX_READINGS
    assert f"only the first {ls.MAX_READINGS} are returned; {gone}" in res.notes
    assert "readings.json has the rest" not in res.notes


def test_two_circuits_with_more_readings_than_are_shown_point_at_both_files(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    for name in ("a.png", "b.png"):
        dr.draw_netlist(dr.nor_transducer(MASKS)).save(files / name)
    res = ls.solve(tmp_path, PROFILE, out=tmp_path / "out")
    one = json.loads((tmp_path / "out" / "1-a.readings.json").read_text())
    two = json.loads((tmp_path / "out" / "2-b.readings.json").read_text())
    assert one == two and len(one) > ls.MAX_READINGS
    assert f"{2 * len(one) - ls.MAX_READINGS} more printable reading(s) are in the readings.json files only" in res.notes
    res = ls.solve(tmp_path, PROFILE, wrap=True, out=tmp_path / "out")
    assert f"only the first {ls.MAX_READINGS} are returned; the readings.json files have the rest" in res.notes


@pytest.mark.parametrize("opts, message", [
    ({"seconds": "abc"}, "option seconds='abc' is not a number of CPU seconds"),
    ({"seconds": None}, "option seconds=None is not a number of CPU seconds"),
    ({"seconds": True}, "option seconds=True is not a number of CPU seconds"),
    ({"seconds": [3]}, r"option seconds=\[3\] is not a number of CPU seconds"),
    ({"seconds": "nan"}, "option seconds='nan' must be more than 0"),
    ({"max_hypotheses": "x"}, "option max_hypotheses='x' is not a whole number of 0 or more"),
    ({"max_hypotheses": -1}, "option max_hypotheses=-1 is not a whole number of 0 or more"),
    ({"max_hypotheses": 2.5}, "option max_hypotheses=2.5 is not a whole number of 0 or more"),
    ({"max_hypotheses": True}, "option max_hypotheses=True is not a whole number of 0 or more"),
    ({"max_hypotheses": None}, "option max_hypotheses=None is not a whole number of 0 or more"),
    ({"texts": 5}, "option texts=5 is not a text or a list of texts"),
    ({"texts": [["a"]]}, r"option texts=\[\['a'\]\] is not a text or a list of texts"),
    ({"texts": [True]}, r"option texts=\[True\] is not a text or a list of texts"),
    ({"texts": {"a": 1}}, r"option texts=\{'a': 1\} is not a text or a list of texts"),
    ({"kinds": 5}, "option kinds=5 is not a text or a list of texts"),
    ({"kinds": "nor,imp"}, "option kinds='nor,imp': unknown gate kind 'imp'"),
    ({"out": 5}, "option out=5 is not a path"),
    ({"netlist": ["a.json"]}, r"option netlist=\['a.json'\] is not a path"),
])
def test_an_option_of_the_wrong_kind_is_refused_by_name_before_anything_is_read(tmp_path, opts, message):
    # a circuit with too few inputs to feed a text: the sweep never gets as far as using `kinds`
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    dr.draw_netlist(_mini()).save(chal / "files" / "mini.png")
    with pytest.raises(ValueError, match="logic_schematic: " + message):
        ls.solve(chal, PROFILE, **{"out": tmp_path / "out", **opts})
    assert not (tmp_path / "out").exists() and not (chal / "recon").exists()


def test_options_take_numbers_as_text_and_whole_numbers_as_texts(board, tmp_path):
    # `--opt seconds=40` arrives as a number, `--opt seconds=4e1` and a quoted value may arrive either way
    res = ls.solve(board, PROFILE, seconds="9999", max_hypotheses=" 3 ", kinds="nor", out=tmp_path / "o1")
    assert "stopped at the cap of 3 hypotheses" in res.notes and "files/board.png: 3 readout hypotheses" in res.notes
    res = ls.solve(board, PROFILE, seconds=9999, max_hypotheses=2.0, kinds=("nor",), out=str(tmp_path / "o2"))
    assert "stopped at the cap of 2 hypotheses" in res.notes and (tmp_path / "o2" / "netlist.json").is_file()
    res = ls.solve(board, PROFILE, texts=[7], kinds="nor", max_hypotheses=1, out=tmp_path / "o3")
    assert f"{''.join(chr(ord('7') ^ m) for m in MASKS)!r} <- every gate nor, text '7'" in res.notes


def test_a_missing_imaging_package_is_blocked_by_name(board, tmp_path, monkeypatch):
    real_import = builtins.__import__

    def no_numpy(name, *a, **k):
        if name == "numpy" or name.startswith("numpy."):
            raise ImportError("No module named 'numpy'", name="numpy")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_numpy)
    res = ls.solve(board, PROFILE, out=tmp_path / "out")
    assert res.status == "blocked" and res.flags == ()
    assert res.notes == "cannot import numpy (No module named 'numpy'): logic_schematic needs Pillow and numpy"
    with pytest.raises(ls.ToolMissing, match="cannot import numpy"):
        ls.detect(board / "files" / "board.png")


def test_cli_prints_the_netlist_summary_and_readings(board, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "pink")
    prof = event.load("pink")
    brand = ls.event_texts(prof)[0]
    body = "".join(chr(ord(c) ^ m) for c in brand for m in MASKS)
    out = tmp_path / "nl.json"
    assert ls.main([str(board / "files" / "board.png"), "--netlist-out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "logigator-like export 976x" in text and "38 gates, 10 inputs (1 tied), 8 outputs" in text
    assert f"  {body!r} <- every gate nor, text {brand!r}" in text
    assert flagfmt.for_profile(prof).find_flags(text) == []
    assert ls.main([str(out), "--event", "pink", "--wrap", "--kinds", "nor"]) == 0      # the netlist it just wrote
    wrapped = f"{prof.flag.prefixes[0]}{{{body}}}"
    assert f"  {wrapped!r} <- every gate nor" in capsys.readouterr().out
    assert ls.main([str(tmp_path / "missing.png")]) == 2
    assert "no such file" in capsys.readouterr().err
    assert ls.main([str(_noise(tmp_path / "photo.png"))]) == 2
    assert "no flat background" in capsys.readouterr().err
    assert ls.main([str(out), "--kinds", "nor,imp"]) == 2         # refused by name, not a traceback from the sweep
    assert "option kinds='nor,imp': unknown gate kind 'imp'" in capsys.readouterr().err


def test_logic_gate_briefs_and_images_route_here(tmp_path, board):
    from ctf.engines import router
    ids = [h.manifest.id for h in router.route("stego", "I love Logic Gates", board / "files")]
    assert ids[0] == "toolkits.logic_schematic"
    ids = [h.manifest.id for h in router.route("misc", "Operation Dawn", board / "files")]
    assert "toolkits.logic_schematic" in ids                      # any image may be a circuit export
    (tmp_path / "notes.txt").write_text("plain words")
    assert "toolkits.logic_schematic" not in [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path)]


def _intake_run(cd, prof):
    """Plan the engine on a challenge folder and run it as intake does, in a child process under the
    Python-level hook guard: the guard intake falls back to where there is no OS sandbox, and the
    stricter one for Python code (no ctypes, no child process). The OS wrapper around it (sandbox-exec,
    unshare) is not exercised here: it does not nest inside the sandbox the suite itself runs under."""
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    guard = G.resolve("hook")
    assert guard.mode == "hook" and not guard.allows_spawn
    plan = E.plan(manifest.discover(), "stego", "I love Logic Gates", cd / "files", guard=guard)
    assert "toolkits.logic_schematic" not in {s.engine for s in plan.skipped}, plan.skipped
    job = next(j for j in plan.jobs if j.engine == "toolkits.logic_schematic")
    ctx = E.Context(challenge_dir=cd, folder=cd / "files", out_root=cd / "recon" / "engines", profile=prof,
                    guard=guard, root=REPO, python=sys.executable, challenge_id="27", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    return job, run


def test_intake_runs_the_engine_with_no_model_and_takes_no_flag_from_a_body(board, tmp_path):
    """The whole no-model path: intake plans the engine on a PNG, runs it under the hook guard (so it
    starts nothing and needs no ctypes), and ends with no flag, because a printable body is not a flag
    in the event format."""
    import shutil
    from ctf import intake
    prof = event.load("pink")
    cd = tmp_path / "27-logic"
    shutil.copytree(board, cd)
    job, run = _intake_run(cd, prof)
    spec = job.manifest.intake
    assert (spec.run, spec.select, spec.spawns) == ("challenge", "files", False)
    assert "py:scipy" not in job.manifest.needs_tools
    # one engine may not outlast the challenge's whole engine budget, and its own budget is under that
    assert ls.DEFAULT_SECONDS < spec.timeout <= intake.DEFAULT_ENGINE_BUDGET
    assert run.result_status == "unsure" and run.flags == ()
    brand = ls.event_texts(prof)[0]
    body = "".join(chr(ord(c) ^ m) for c in brand for m in MASKS)
    first = json.loads((cd / "recon" / "logic_schematic" / "readings.json").read_text())[0]
    assert (first["stream"], first["text"], first["kinds"]) == (body, brand, {"0": "nor"})


def test_intake_takes_no_flag_from_a_reading_that_opens_the_flag_format(tmp_path):
    """End to end, under an event whose flag body may hold spaces and whose submit mode is auto: the
    circuit reads `PREFIX{` for the event's name. Printed as it is, the result JSON's own closing brace
    would complete a match in the engine's output, and intake would hold an inferred value as a found
    flag. The engine escapes it; intake finds nothing."""
    prof = event.load("pink")
    ff = flagfmt.for_profile(prof)
    assert prof.rules.submit_mode == "auto" and ff.find_flags("PINK{a b}") == ["PINK{a b}"]
    brand = ls.event_texts(prof)[0]
    open_flag = f"{prof.flag.prefixes[0]}{{"
    assert len(open_flag) == len(brand) == len(set(brand))
    cd = tmp_path / "27-logic"
    (cd / "files").mkdir(parents=True)
    dr.draw_netlist(_pla([(brand, open_flag)], states=((0, 1),))).save(cd / "files" / "board.png")
    _, run = _intake_run(cd, prof)
    assert run.result_status == "unsure" and run.flags == ()
    out = (cd / run.output).read_text()
    assert ff.find_flags(out) == [] and f"'{open_flag[:-1]}\\\\x7b' <- every gate nor, text {brand!r}" in out
    readings = json.loads((cd / "recon" / "logic_schematic" / "readings.json").read_text())
    assert readings[0]["stream"] == open_flag                     # the reading was made, and is kept as read
