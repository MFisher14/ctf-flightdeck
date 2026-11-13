"""B-119: render_candidates' composition axis (field subset x order x rendering x join) and the
decimal-places kind.

The composition space is checked against an independent brute-force product, so a change to the
generator's loops (a skipped subset, a join dropped, a rendering never tried) fails here. Every value
is synthetic.
"""
from __future__ import annotations

import itertools
import math

import pytest

import render_candidates as RC

A = ("a", [("as_stored", "A1"), ("upper", "AA"), ("lower", "aa")])
B = ("b", [("as_stored", "B1"), ("hex", "0xB")])
C = ("c", [("as_stored", "C1")])
JOINS2 = (("colon", ":"), ("none", ""))


def brute(fields, joins, lo, hi, dmax, permute):
    """Every composition by plain nested loops: the oracle compose_axis is compared with."""
    out = set()
    n = len(fields)
    for k in range(lo, hi + 1):
        for subset in itertools.combinations(range(n), k):
            for order in (itertools.permutations(subset) if permute else [subset]):
                for picks in itertools.product(*[fields[i][1] for i in order]):
                    dev = sum(1 for i, p in zip(order, picks) if p != fields[i][1][0])
                    if dev > dmax:
                        continue
                    for jname, sep in (joins if k > 1 else [(None, "")]):
                        out.add((tuple(fields[i][0] for i in order), tuple(p[0] for p in picks), jname,
                                 sep.join(p[1] for p in picks)))
    return out


@pytest.mark.parametrize("fields,lo,hi,dmax,permute", [
    ([A, B, C], 1, 3, 3, True),
    ([A, B, C], 2, 3, 1, True),
    ([A, B, C], 1, 2, 0, True),
    ([A, B, C], 1, 3, 3, False),
    ([A, B], 2, 2, 2, True),
    ([C], 1, 1, 1, True),
], ids=["all", "min2-dev1", "max2-dev0", "given-order", "pair", "single"])
def test_compose_axis_is_exactly_the_brute_force_space(fields, lo, hi, dmax, permute):
    got = list(RC.compose_axis(fields, joins=JOINS2, min_fields=lo, max_fields=hi, max_deviations=dmax,
                               permute=permute))
    want = brute(fields, JOINS2, lo, hi, dmax, permute)
    assert len(got) == len(set(got)), "a composition was yielded twice"
    assert set(got) == want
    assert RC.compose_size(fields, joins=JOINS2, min_fields=lo, max_fields=hi, max_deviations=dmax,
                           permute=permute) == len(want)


def test_the_first_composition_is_every_field_in_the_given_order_as_stored_colon_joined():
    first = next(RC.compose_axis([A, B, C]))
    assert first == RC.Composed(("a", "b", "c"), ("as_stored", "as_stored", "as_stored"), "colon", "A1:B1:C1")
    assert first.text == "A1:B1:C1" and first.join == "colon"


def test_compositions_come_best_first():
    got = list(RC.compose_axis([A, B, C], joins=JOINS2))
    default = {"a": "as_stored", "b": "as_stored", "c": "as_stored"}
    devs = [sum(1 for f, r in zip(c.fields, c.renders) if r != default[f]) for c in got]
    assert devs == sorted(devs), "fewer re-rendered fields must come first"
    assert set(devs) == {0, 1, 2}
    zero = [c for c, d in zip(got, devs) if d == 0]
    sizes = [len(c.fields) for c in zero]
    assert sizes == sorted(sizes, reverse=True), "larger subsets first within one depth"
    # the given order before any other order of the same fields, and the joins in their order
    assert [(c.fields, c.join) for c in zero[:4]] == [
        (("a", "b", "c"), "colon"), (("a", "b", "c"), "none"),
        (("a", "c", "b"), "colon"), (("a", "c", "b"), "none")]


def test_one_field_alone_is_not_joined_and_is_listed_once_per_rendering():
    got = list(RC.compose_axis([A], joins=RC.JOINS))
    assert [(c.renders, c.join, c.text) for c in got] == [
        (("as_stored",), None, "A1"), (("upper",), None, "AA"), (("lower",), None, "aa")]


def test_permute_false_keeps_the_given_order_in_every_subset():
    got = list(RC.compose_axis([A, B, C], joins=JOINS2, permute=False, max_deviations=0))
    assert {c.fields for c in got} == {("a", "b", "c"), ("a", "b"), ("a", "c"), ("b", "c"), ("a",), ("b",), ("c",)}


def test_limit_cuts_the_tail_and_the_size_is_the_uncut_count():
    full = list(RC.compose_axis([A, B, C], joins=JOINS2))
    assert RC.compose_size([A, B, C], joins=JOINS2) == len(full) > 10
    assert list(RC.compose_axis([A, B, C], joins=JOINS2, limit=7)) == full[:7]
    assert list(RC.compose_axis([A, B, C], joins=JOINS2, limit=0)) == []
    assert list(RC.compose_axis([A, B, C], joins=JOINS2, limit=10 ** 9)) == full


def test_size_is_computed_not_enumerated_for_a_large_space():
    # 10 fields, 5 renderings each, 9 joins: far too many to list, sized in closed form
    big = [(f"f{i}", [(f"r{j}", f"{i}{j}") for j in range(5)]) for i in range(10)]
    want = 0
    for k in range(1, 11):
        ways = sum(math.comb(k, d) * 4 ** d for d in range(k + 1))          # = 5 ** k
        want += math.comb(10, k) * math.factorial(k) * (9 if k > 1 else 1) * ways
    assert RC.compose_size(big) == want > 10 ** 12


def test_the_default_joins_start_with_colon_and_hold_pipe_and_none():
    names = [n for n, _ in RC.JOINS]
    assert names[0] == "colon" and dict(RC.JOINS)["colon"] == ":"
    assert dict(RC.JOINS)["pipe"] == "|" and dict(RC.JOINS)["none"] == ""
    assert len(names) == len(set(names))


@pytest.mark.parametrize("call,why", [
    (lambda: RC.compose_size([]), "no fields"),
    (lambda: RC.compose_size([A, A]), "used twice"),
    (lambda: RC.compose_size([("x", [])]), "no rendering"),
    (lambda: RC.compose_size([("x", [("r", "1"), ("r", "2")])]), "names a rendering twice"),
    (lambda: RC.compose_size([A, B], min_fields=3), "min_fields"),
    (lambda: RC.compose_size([A, B], min_fields=0), "min_fields"),
    (lambda: RC.compose_size([A, B], max_deviations=-1), "max_deviations"),
    (lambda: RC.compose_size([A, B], joins=[]), "no join"),
    (lambda: RC.compose_size([(f"f{i}", [("r", "v")]) for i in range(RC.COMPOSE_MAX_FIELDS + 1)]), "at most"),
    (lambda: list(RC.compose_axis([("x", "not options")])), "pairs"),
    (lambda: list(RC.compose_axis(["x"])), "each field is"),
], ids=["empty", "dup-name", "no-render", "dup-render", "min>n", "min0", "dev<0", "no-join", "too-many",
        "options-shape", "field-shape"])
def test_a_malformed_composition_call_is_named(call, why):
    with pytest.raises(ValueError, match=why):
        call()


# ------------------------------------------------------------------------------------- decimal places

def test_decimal_renders_fixed_places_most_common_first():
    assert RC.render(31.4072, "decimal") == [                 # an invented number, like every value here
        ("dp_1", "31.4"), ("dp_2", "31.41"), ("dp_3", "31.407"), ("dp_4", "31.4072"), ("dp_5", "31.40720"),
        ("dp_6", "31.407200"), ("dp_0", "31"), ("dp_7", "31.4072000"), ("dp_8", "31.40720000")]


def test_decimal_keeps_the_shortest_form_and_an_unusual_stored_spelling():
    got = dict(RC.render(208.61735042915367, "decimal"))
    assert got["dp_1"] == "208.6" and got["shortest"] == "208.61735042915367"
    got = dict(RC.render("0.000300", "decimal"))          # the stored spelling is dp_6: named once
    assert got["dp_6"] == "0.000300" and got["dp_4"] == "0.0003" and "as_stored" not in got
    got = dict(RC.render("4.5e1", "decimal"))            # shortest is 45.0, which dp_1 already spells
    assert got["as_stored"] == "4.5e1" and got["dp_1"] == "45.0" and "shortest" not in got
    assert dict(RC.render(3, "decimal"))["dp_2"] == "3.00"


def test_decimal_max_places_bounds_the_list():
    assert RC.render(1.375, "decimal", max_places=2) == [
        ("dp_1", "1.4"), ("dp_2", "1.38"), ("dp_0", "1"), ("shortest", "1.375")]


@pytest.mark.parametrize("bad", [True, "abc", "1.2.3", "", float("nan"), float("inf"), None, b"1.5", [1.5]])
def test_decimal_declines_what_is_not_one_real_number(bad):
    assert RC.render(bad, "decimal") == []


def test_the_new_axes_change_no_existing_candidate_list():
    # the judge-facing lists other lanes send are as they were: no colon separator, no new integer spelling
    assert RC.render(1024, "integer") == [("integer", "1024"), ("hex_0x", "0x400"), ("hex_0x_byte", "0x0400"),
                                          ("hex_bare", "400")]
    assert [name.split("+")[1] for name, _ in RC.order_axis(["b", "a"])[:5]] == [
        "comma", "comma_space", "space", "pipe", "json"]
    assert RC.classify(None, 31.4072) is None and RC.classify(None, "31.4072") is None   # never `decimal`
