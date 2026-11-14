"""B-258: the shared expectation generator (ctf/expectations.py), also the base for B-196.

Targets are small functions written here or in a temp file; outputs are compared to literal values.
"""
from __future__ import annotations

import json

import pytest

from ctf import expectations as X


def answers(data: bytes, *, upper: bool = False):
    head = data[:4].hex()
    return {"q_len": len(data), "q_head": head.upper() if upper else head, "q_none": None}


def boom(data):
    raise ValueError("bad sample")


def test_generate_runs_each_case_and_records_outputs_and_errors():
    cases = [X.case("a", b"\x01\x02\x03\x04\x05"), X.case("b", b"\xff", upper=True)]
    doc = X.generate(answers, cases, target_spec="t.py:answers")
    assert doc == {"schema": 1, "target": "t.py:answers", "cases": {
        "a": {"output": {"q_len": 5, "q_head": "01020304", "q_none": None}},
        "b": {"output": {"q_len": 1, "q_head": "FF", "q_none": None}}}}
    err = X.generate(boom, [X.case("x", b"")])
    assert err["cases"]["x"] == {"error": "ValueError: bad sample"}


def test_duplicate_case_ids_and_bad_ids_are_refused():
    with pytest.raises(X.ExpectationError, match="twice"):
        X.generate(answers, [X.case("a", b""), X.case("a", b"x")])
    with pytest.raises(X.ExpectationError, match="without '/'"):
        X.case("a/b", b"")
    with pytest.raises(X.ExpectationError, match="not a Case"):
        X.generate(answers, [("a", b"")])


class Weird:
    pass


def test_normalize_maps_python_values_to_json_and_refuses_the_rest():
    class Prior(str):
        pass
    got = X.normalize({"b": b"\x00\xff", "t": (1, 2), "s": {3, 1}, "p": Prior("x"), "flag": True})
    assert got == {"b": {"$bytes": "00ff"}, "t": [1, 2], "s": [1, 3], "p": "x", "flag": True}
    assert type(got["p"]) is str
    with pytest.raises(X.ExpectationError, match="Weird"):
        X.normalize({"k": Weird()})
    with pytest.raises(X.ExpectationError, match="not a string"):
        X.normalize({1: "x"})
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(X.ExpectationError, match="no JSON form"):
            X.normalize({"k": [bad]})
    assert X.normalize(1.5) == 1.5 and type(X.normalize(True)) is bool
    assert X.denormalize({"k": {"$bytes": "00ff"}, "l": [{"$bytes": "41"}]}) == {"k": b"\x00\xff", "l": [b"A"]}


def test_a_set_normalizes_in_one_order_whatever_its_members():
    words = {f"w{i:02d}" for i in range(40)}
    assert X.normalize(words) == sorted(words)
    # mixed members sort by their JSON text: '"a"' < '"b"' < '2' < '[3]'
    assert X.normalize({"b", 2, "a", frozenset({3})}) == ["a", "b", 2, [3]]


def test_load_target_drops_a_module_that_fails_to_import(tmp_path):
    import sys
    (tmp_path / "broken_b258.py").write_text("raise RuntimeError('half loaded')\n")
    before = set(sys.modules)
    with pytest.raises(RuntimeError, match="half loaded"):
        X.load_target("broken_b258.py:f", root=tmp_path)
    assert not [m for m in set(sys.modules) - before if m.startswith("expect_target_")]


def test_write_is_deterministic_and_load_round_trips(tmp_path):
    doc = X.generate(answers, [X.case("z", b"zz"), X.case("a", b"aa")])
    p = X.write(tmp_path / "e.json", doc)
    text = p.read_text()
    assert text.endswith("}\n") and text.index('"a"') < text.index('"z"')
    assert X.load(p) == doc
    X.write(tmp_path / "e2.json", X.load(p))
    assert (tmp_path / "e2.json").read_text() == text
    (tmp_path / "bad.json").write_text('{"schema": 1, "cases": {"a": {}}}')
    with pytest.raises(X.ExpectationError, match="exactly one"):
        X.load(tmp_path / "bad.json")
    with pytest.raises(X.ExpectationError, match="no expectations file"):
        X.load(tmp_path / "missing.json")


def test_compare_names_every_difference():
    old = X.generate(answers, [X.case("a", b"\x01\x02"), X.case("gone", b"")])
    new = X.generate(answers, [X.case("a", b"\x01\x02\x03"), X.case("added", b"")])
    diffs = {(d.case, d.path): (d.expected, d.actual) for d in X.compare(old, new)}
    assert diffs[("a", "['q_len']")] == (2, 3)
    assert diffs[("a", "['q_head']")] == ("0102", "010203")
    assert diffs[("gone", "")][1] is X.MISSING
    assert diffs[("added", "")][0] is X.MISSING
    assert len(diffs) == 4
    assert X.compare(old, old) == []


def test_diff_values_tells_bool_from_int_and_absent_from_none():
    assert X.diff_values({"k": True}, {"k": 1}) != []
    assert X.diff_values({"k": None}, {}) == [X.Diff("", "['k']", None, X.MISSING)]
    assert X.diff_values([1, 2], [1, 2, 3])[0].path == ".len"
    assert X.diff_values(1, 1.0) == []


def test_pins_flatten_cases_and_refuse_a_silent_pick():
    doc = X.generate(answers, [X.case("a", b"\x01"), X.case("b", b"\x01\x02"), X.case("e", b"")])
    doc["cases"]["e"] = {"error": "ValueError: bad sample"}
    # cases disagree on q_len and q_head: their bare forms are left out and named, the case/key
    # forms stay, and the key they agree on keeps its bare form
    both = X.pins(doc)
    assert dict(both) == {"q_none": None, "a/q_len": 1, "a/q_head": "01", "a/q_none": None,
                          "b/q_len": 2, "b/q_head": "0102", "b/q_none": None}
    assert both.ambiguous == {"q_head", "q_len"}
    assert both.cases == {"a", "b", "e"}            # an errored case is still a case id
    a = X.pins(doc, case="a")
    assert a == {"q_len": 1, "q_head": "01", "q_none": None, "a/q_len": 1, "a/q_head": "01", "a/q_none": None}
    assert a.ambiguous == set() and a.cases == {"a", "b", "e"}
    assert X.pins({"q1": 1}).cases == set()         # a plain object has no case ids
    with pytest.raises(X.ExpectationError, match="no case 'c'"):
        X.pins(doc, case="c")
    same = X.generate(answers, [X.case("a", b"\x01"), X.case("b", b"\x01")])
    both = X.pins(same)
    assert both["q_head"] == "01" and both["b/q_len"] == 1
    assert X.pins({"q1": {"$bytes": "41"}, "q2": 7}) == {"q1": b"A", "q2": 7}
    scalar = X.generate(len, [X.case("n", b"abc")])
    assert X.pins(scalar) == {"n": 3}


def test_load_target_by_file_and_by_module(tmp_path):
    (tmp_path / "helper_b258.py").write_text("K = 7\n")
    (tmp_path / "tgt.py").write_text("import helper_b258\ndef f(x):\n    return x * helper_b258.K\n")
    fn = X.load_target("tgt.py:f", root=tmp_path)
    assert fn(3) == 21
    assert X.load_target("json:dumps") is json.dumps
    for bad, why in (("tgt.py", "expected"), ("tgt.py:nope", "no callable"), ("missing.py:f", "no file"),
                     ("tgt.py:1x", "not a function name")):
        with pytest.raises(X.ExpectationError, match=why):
            X.load_target(bad, root=tmp_path)
