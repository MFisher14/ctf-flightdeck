"""The SolverResult contract: its invariants, its JSON form, and strict reading of output
that came from an engine (untrusted)."""

from __future__ import annotations

import ast
import json
import random
from pathlib import Path

import pytest

from ctf_flightdeck.l1 import result as result_module
from ctf_flightdeck.l1.result import SCHEMA, STATUSES, Cost, Evidence, ResultError, SolverResult

FULL = SolverResult(
    status="solved",
    flags=("t{one}", "t{two}"),
    evidence=(Evidence("decode", "three base64 layers", "layers.txt", 12), Evidence("match", "format matched")),
    cost=Cost(seconds=1.25, usd=0.5, tokens=42),
    engine="decode.b64",
    challenge_id="mille-feuille",
    notes="peeled   and é",
)


def test_a_result_round_trips_exactly_through_a_dict_and_json():
    assert SolverResult.from_dict(FULL.to_dict()) == FULL
    assert SolverResult.from_json(FULL.to_json()) == FULL
    assert SolverResult.from_json(FULL.to_json().encode()) == FULL
    minimal = SolverResult("none")
    assert SolverResult.from_json(minimal.to_json()) == minimal


def test_the_dict_form_has_the_schema_every_field_and_lists_for_tuples():
    d = FULL.to_dict()
    assert d == {
        "schema": 1,
        "status": "solved",
        "flags": ["t{one}", "t{two}"],
        "evidence": [
            {"kind": "decode", "detail": "three base64 layers", "path": "layers.txt", "offset": 12},
            {"kind": "match", "detail": "format matched", "path": None, "offset": None},
        ],
        "cost": {"seconds": 1.25, "usd": 0.5, "tokens": 42},
        "engine": "decode.b64",
        "challenge_id": "mille-feuille",
        "notes": "peeled   and é",
    }
    assert SCHEMA == 1 and STATUSES == ("solved", "candidate", "none", "unsure", "blocked")


def test_to_json_is_one_ascii_line_even_when_a_flag_holds_a_line_separator():
    line = SolverResult("candidate", flags=("t{a b}", "t{c\nd}")).to_json()
    assert line.isascii()
    assert len(line.splitlines()) == 1  # splitlines() also splits on U+2028
    assert SolverResult.from_json(line).flags == ("t{a b}", "t{c\nd}")


def test_lists_are_kept_as_tuples_so_a_result_stays_immutable_and_hashable():
    r = SolverResult("solved", flags=["t{x}"], evidence=[Evidence("oracle", "the oracle said yes")])
    assert r.flags == ("t{x}",) and isinstance(r.evidence, tuple)
    hash(r)
    assert Cost(seconds=2, usd=1).seconds == 2.0 and isinstance(Cost(seconds=2).seconds, float)


@pytest.mark.parametrize(
    ("kwargs", "words"),
    [
        ({"status": "accepted"}, "status must be one of"),
        ({"status": "SOLVED"}, "status must be one of"),
        ({"status": "solved", "flags": ("t{x}",)}, "evidence"),  # "found" needs a reason
        ({"status": "solved", "evidence": (Evidence("decode", "d"),)}, "at least one flag"),
        ({"status": "candidate"}, "candidate result needs at least one flag"),
        ({"status": "none", "flags": ("t{x}",)}, "none result carries no flags"),
        ({"status": "blocked", "flags": ("t{x}",), "notes": "zsteg"}, "blocked result carries no flags"),
        ({"status": "blocked"}, "notes naming what is missing"),
        ({"status": "blocked", "notes": "   "}, "notes naming what is missing"),
        ({"status": "candidate", "flags": ("",)}, "non-empty strings"),
        ({"status": "candidate", "flags": (" ",)}, "non-empty strings"),
        ({"status": "candidate", "flags": (7,)}, "non-empty strings"),
        ({"status": "candidate", "flags": "t{x}"}, "flags must be a list"),  # not iterated as characters
        ({"status": "none", "evidence": ({"kind": "x", "detail": "y"},)}, "Evidence objects"),
        ({"status": "none", "cost": {"seconds": 1}}, "Cost object"),
        ({"status": "none", "engine": 3}, "engine must be a string"),
        ({"status": "none", "challenge_id": ["x"]}, "challenge_id must be a string"),
        ({"status": "none", "notes": None}, "notes must be a string"),
    ],
)
def test_breaking_an_invariant_is_a_result_error(kwargs, words):
    with pytest.raises(ResultError, match=words):
        SolverResult(**kwargs)


def test_the_statuses_that_need_nothing_more_are_valid_bare():
    assert SolverResult("none").flags == ()
    assert SolverResult("unsure", flags=("t{maybe}",)).flags == ("t{maybe}",)
    assert SolverResult("blocked", notes="zsteg is not installed").notes


@pytest.mark.parametrize(
    ("build", "words"),
    [
        (lambda: Evidence("", "x"), "kind must be a non-empty string"),
        (lambda: Evidence("decode", None), "detail must be a string"),
        (lambda: Evidence("decode", "x", path=Path("a")), "path must be a string"),
        (lambda: Evidence("decode", "x", offset=-1), "offset"),
        (lambda: Evidence("decode", "x", offset=True), "offset"),
        (lambda: Cost(seconds=-1), "cost.seconds"),
        (lambda: Cost(seconds=float("nan")), "cost.seconds"),
        (lambda: Cost(usd=float("inf")), "cost.usd"),
        (lambda: Cost(seconds=True), "cost.seconds"),
        (lambda: Cost(tokens=1.5), "cost.tokens"),
        (lambda: Cost(tokens=-3), "cost.tokens"),
        (lambda: Cost(seconds=10**400), "cost.seconds is too large"),
        (lambda: Cost(usd=-(10**400)), "cost.usd is too large"),
    ],
)
def test_evidence_and_cost_check_their_fields(build, words):
    with pytest.raises(ResultError, match=words):
        build()


HOSTILE = [None, True, False, 0, 1, -1, 2**63, 10**308, 10**400, -(10**400), 1.5, -0.0, 1e308, "", " ", "t{x}", "\ud800",
           [], [1], ["t{x}"], {}, {"a": 1}, [{"kind": "k", "detail": "d"}], [{"kind": "k", "detail": "d", "offset": 10**400}],
           {"seconds": 10**400}, {"usd": 10**400}, {"tokens": 10**400}, [{"kind": "k", "detail": "d", "path": "\udcff"}]]


def test_any_value_in_any_field_is_read_or_refused_with_a_result_error():
    # The runner catches ResultError only: any other exception from one engine's line would
    # stop every engine on the challenge.
    rng = random.Random(7)
    keys = ["schema", "status", "flags", "evidence", "cost", "engine", "challenge_id", "notes"]
    for _ in range(3000):
        doc = {"schema": 1, "status": rng.choice(STATUSES)}
        for key in rng.sample(keys, rng.randint(1, 4)):
            doc[key] = rng.choice(HOSTILE)
        line = json.dumps(doc)  # Python writes any int, however long
        try:
            SolverResult.from_json(line)
        except ResultError:
            pass


@pytest.mark.parametrize(
    ("data", "words"),
    [
        ({"schema": 1, "status": "none", "verdict": "yes"}, 'unknown field "verdict"'),
        ({"schema": 2, "status": "none"}, "schema 2 is not supported"),
        ({"schema": True, "status": "none"}, "schema true is not supported"),
        ({"schema": "1", "status": "none"}, "is not supported"),
        ({"status": "none"}, '"schema" is missing'),
        ({"schema": 1}, '"status" is missing'),
        ({"schema": 1, "status": "candidate", "flags": "t{x}"}, "flags must be a list"),
        ({"schema": 1, "status": "none", "evidence": {"kind": "x"}}, "evidence must be a list"),
        ({"schema": 1, "status": "none", "evidence": ["x"]}, "each evidence item must be an object"),
        ({"schema": 1, "status": "none", "evidence": [{"kind": "x", "detail": "y", "where": 1}]}, 'evidence has unknown field "where"'),
        ({"schema": 1, "status": "none", "evidence": [{"kind": "x"}]}, "evidence.detail is missing"),
        ({"schema": 1, "status": "none", "cost": {"seconds": 1, "dollars": 2}}, 'cost has unknown field "dollars"'),
        ({"schema": 1, "status": "none", "cost": 3}, "cost must be an object"),
        ({"schema": 1, "status": "solved", "flags": ["t{x}"]}, "evidence"),
    ],
)
def test_reading_a_result_is_strict(data, words):
    with pytest.raises(ResultError, match=words):
        SolverResult.from_dict(data)


@pytest.mark.parametrize(
    ("text", "words"),
    [
        ("", "not JSON"),
        ("solved: t{x}", "not JSON"),
        ('["schema", 1]', "must be a JSON object"),
        ('{"schema": 1, "status": "none", "status": "solved"}', '"status" is given twice'),
        ('{"schema": 1, "status": "none", "cost": {"seconds": NaN}}', "NaN is not a JSON number"),
        ('{"schema": 1, "status": "none", "cost": {"usd": Infinity}}', "Infinity is not a JSON number"),
        (b'{"schema": 1, "status": "none", "notes": "\xff"}', "UTF-8"),
        ("[" * 100_000 + "]" * 100_000, "nesting too deep"),
        # whole numbers too big for a float: float() raises OverflowError, which must not escape
        ('{"schema": 1, "status": "none", "cost": {"seconds": 1' + "0" * 400 + "}}", "cost.seconds is too large"),
        ('{"schema": 1, "status": "none", "cost": {"usd": 1' + "0" * 309 + "}}", "cost.usd is too large"),
        ('{"schema": 1, "status": "none", "cost": {"seconds": -1' + "0" * 400 + "}}", "cost.seconds is too large"),
    ],
)
def test_from_json_turns_every_bad_line_into_a_result_error(text, words):
    with pytest.raises(ResultError, match=words):
        SolverResult.from_json(text)


def test_an_error_message_never_carries_a_long_untrusted_value():
    long_name = "x" * 500
    with pytest.raises(ResultError) as caught:
        SolverResult.from_dict({"schema": 1, "status": "none", long_name: 1})
    assert len(str(caught.value)) < 200


def test_result_and_the_boot_script_parse_as_python_3_8_so_an_engine_can_use_any_python3():
    # A python engine runs under the player's python3 (or a lane image's), not flightdeck's.
    for module in (result_module.__file__, Path(result_module.__file__).with_name("_boot.py")):
        ast.parse(Path(module).read_text(), feature_version=(3, 8))  # refuses match statements, except*, ...
    imports = {
        node.names[0].name if isinstance(node, ast.Import) else node.module
        for node in ast.walk(ast.parse(Path(result_module.__file__).read_text()))
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    assert imports <= {"__future__", "json", "math", "dataclasses"}  # stdlib only


def test_json_dumps_of_to_dict_and_to_json_agree():
    assert json.loads(FULL.to_json()) == FULL.to_dict()
    assert FULL.to_json(indent=2).count("\n") > 3  # keyword arguments reach json.dumps
