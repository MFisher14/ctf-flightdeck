"""B-042: tools/run.py's split_sets hands every set its own delivery, and nothing else.

The runner's split is what every runner, replay and gate reads an attempt through. These tests feed it
synthetic Mastery attempts in the three Huntress shapes (one same-named delivery per set, named by the
questions or in set order; one bundle with a numbered member per set) and the shapes it used to answer
from a neighbour's delivery (more sets than deliveries, a set the bundle has no member for), with a solver
that answers the sha256 of the member it was handed."""
from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest

from ctf.adapt import setpool

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import run  # noqa: E402  (tools/run.py: split_sets and solve_all import without the Game Master client)


def zipped(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members:
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0)), body)
    return buf.getvalue()


def note(n):
    return f"the note of set {n}\n".encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def attempt(names, artifacts_text, sets=None):
    """`artifacts_text(n)` is the artifact text of set n's one question (id setN.sha256)."""
    sets = sets if sets is not None else range(1, len(artifacts_text) + 1)
    qs = [{"id": f"set{n}.sha256", "question": "sha256 of note.txt?", "artifact": artifacts_text[i], "set": n}
          for i, n in enumerate(sets)]
    return {"attempt_id": "synthetic", "questions": qs, "answer_ids": [x["id"] for x in qs],
            "artifacts": [{"filename": name} for name in names]}


class Sha:
    """Answers the sha256 of note.txt as the set's own files hold it, and records every call."""

    def __init__(self):
        self.calls = []

    def solve_set(self, questions, files, ctx):
        self.calls.append(ctx["set"])
        data = files.get("note.txt")
        return {x["qid"]: None if data is None else sha(data) for x in questions}


def by_set(sets):
    return {n: (qs, files, ctx) for n, qs, files, ctx in sets}


# --------------------------------------------------------------------------- the three proven shapes

def test_same_named_deliveries_named_by_the_questions_reach_their_own_set():
    # Day 1: every delivery is evidence.zip and holds note.txt; the questions name theirs. Set 1 names
    # delivery 3 here, so a split by position alone would hand it delivery 1.
    blobs = [zipped([("note.txt", note(k))]) for k in (1, 2, 3)]
    att = attempt(["evidence.zip"] * 3, ["delivery 3: evidence.zip -> note.txt", "delivery 2: evidence.zip -> note.txt",
                                         "delivery 1: evidence.zip -> note.txt"])
    notes = []
    got = by_set(run.split_sets(att, blobs, [], notes))
    assert [got[n][2]["delivery"] for n in (1, 2, 3)] == [blobs[2], blobs[1], blobs[0]]
    assert [got[n][1]["note.txt"] for n in (1, 2, 3)] == [note(3), note(2), note(1)]
    assert notes == [] and all("delivery_unmapped" not in got[n][2] for n in got)
    solver, errors = Sha(), []
    answers, _ = run.solve_all(solver, run.split_sets(att, blobs), None, errors)
    assert answers == {"set1.sha256": sha(note(3)), "set2.sha256": sha(note(2)), "set3.sha256": sha(note(1))}
    assert errors == []


def test_unnamed_deliveries_pair_with_the_sets_in_set_order():
    # Day 2: two evidence.zip, questions say evidence-0N.zip (a name no delivery carries)
    blobs = [zipped([("note.txt", note(k))]) for k in (1, 2)]
    att = attempt(["evidence.zip"] * 2, ["evidence-01.zip -> note.txt", "evidence-02.zip -> note.txt"])
    got = by_set(run.split_sets(att, blobs))
    assert got[1][1]["note.txt"] == note(1) and got[2][1]["note.txt"] == note(2)
    assert got[1][2]["delivery_name"] == "evidence.zip" and got[2][2]["delivery"] is blobs[1]
    assert got[1][2]["siblings"] == {1: blobs[0], 2: blobs[1]}


def test_a_bundles_numbered_member_serves_its_set_whatever_the_archive_order():
    inner = {k: zipped([("note.txt", note(k))]) for k in (1, 2)}
    bundle = zipped([("evidence-02.zip", inner[2]), ("readme.txt", b"hello"), ("evidence-01.zip", inner[1])])
    att = attempt(["mastery.zip"], ["evidence-01.zip -> note.txt", "evidence-02.zip -> note.txt"])
    got = by_set(run.split_sets(att, [bundle]))
    assert [(got[n][2]["delivery_name"], got[n][2]["delivery"]) for n in (1, 2)] == [
        ("evidence-01.zip", inner[1]), ("evidence-02.zip", inner[2])]
    assert got[1][1]["note.txt"] == note(1) and got[2][1]["note.txt"] == note(2)
    assert "readme.txt" not in got[1][1], "a set's files are its own member's, not the bundle's"


def test_one_set_still_sees_every_delivery():
    blobs = [zipped([("a.txt", b"A")]), zipped([("b.txt", b"B")])]
    att = {"questions": [{"id": "first", "question": "?"}], "answer_ids": ["first"],
           "artifacts": [{"filename": "one.zip"}, {"filename": "two.zip"}]}
    ((n, _, files, ctx),) = run.split_sets(att, blobs)
    assert n == 0 and files["a.txt"] == b"A" and files["b.txt"] == b"B"
    assert ctx["delivery_name"] == "one.zip" and "siblings" not in ctx
    # no delivery at all (a live-target attempt): one set, no files, and not reported as unmapped
    notes = []
    ((_, _, files, ctx),) = run.split_sets(dict(att, artifacts=[]), [], [], notes)
    assert files == {} and ctx["delivery"] == b"" and "delivery_unmapped" not in ctx and notes == []


# --------------------------------------------------------------------------- fail closed

def test_more_sets_than_deliveries_no_longer_reads_the_last_delivery():
    # The old split gave set 3 the last delivery (set 2's file): a well-formed answer from the wrong set.
    blobs = [zipped([("note.txt", note(k))]) for k in (1, 2)]
    att = attempt(["evidence.zip"] * 2, ["note.txt"] * 3)
    notes = []
    sets = run.split_sets(att, blobs, [], notes)
    for n, qs, files, ctx in sets:
        assert files == {} and ctx["delivery"] == b"" and ctx["delivery_name"] is None
        assert "do not pair one to one with 2 deliveries" in ctx["delivery_unmapped"]
    assert len(notes) == 3 and all(f"set {n}: no delivery is proven to be its own" in notes[n - 1] for n in (1, 2, 3))
    assert "siblings" in sets[0][3] and sets[0][3]["siblings"] == {}
    solver, errors = Sha(), []
    answers, timed_out = run.solve_all(solver, sets, None, errors)
    assert answers == {} and not timed_out and solver.calls == [], "the solver is not asked about a set with no delivery"
    assert len(errors) == 3 and errors[2].startswith("set 3: no delivery is proven to be its own (")
    assert "so it was not solved" in errors[2] and "not downloaded" not in errors[2]


def test_a_set_naming_a_delivery_the_attempt_lacks_is_the_only_one_left_out():
    blobs = [zipped([("note.txt", note(k))]) for k in (1, 2)]
    att = attempt(["evidence.zip"] * 2, [f"delivery {k}: evidence.zip -> note.txt" for k in (1, 2, 3)])
    notes = []
    sets = run.split_sets(att, blobs, [], notes)
    got = by_set(sets)
    assert got[1][1]["note.txt"] == note(1) and got[2][1]["note.txt"] == note(2)
    assert got[3][1] == {} and "name delivery 3" in got[3][2]["delivery_unmapped"]
    assert len(notes) == 1 and notes[0].startswith("set 3: no delivery is proven to be its own")
    assert got[1][2]["siblings"] == {1: blobs[0], 2: blobs[1]}, "an unmapped set lends no bytes to its siblings"
    solver, errors = Sha(), []
    answers, _ = run.solve_all(solver, sets, None, errors)
    assert answers == {"set1.sha256": sha(note(1)), "set2.sha256": sha(note(2))} and solver.calls == [1, 2]
    assert len(errors) == 1 and errors[0].startswith("set 3: no delivery is proven")


def test_a_set_the_bundle_has_no_member_for_no_longer_reads_the_whole_bundle():
    # The old split handed set 2 the whole bundle, where note.txt is set 1's.
    inner = zipped([("note.txt", note(1))])
    bundle = zipped([("evidence-01.zip", inner), ("loose.txt", b"x")])
    att = attempt(["mastery.zip"], ["evidence-01.zip -> note.txt", "evidence-02.zip -> note.txt"])
    notes = []
    got = by_set(run.split_sets(att, [bundle], [], notes))
    assert got[1][1]["note.txt"] == note(1)
    assert got[2][1] == {} and got[2][2]["delivery"] == b""
    assert "no member of the bundle is numbered 2" in got[2][2]["delivery_unmapped"]
    assert len(notes) == 1 and "its 1 question(s) are left unanswered" in notes[0]


def test_a_bundle_named_whole_by_the_questions_is_still_read_whole():
    bundle = zipped([("alpha.txt", b"A"), ("beta.txt", b"B")])
    att = attempt(["bundle.zip"], ["delivery 1: bundle.zip -> alpha.txt", "delivery 1: bundle.zip -> beta.txt"])
    notes = []
    got = by_set(run.split_sets(att, [bundle], [], notes))
    assert notes == [] and got[1][2]["delivery"] == bundle and got[2][2]["delivery_name"] == "bundle.zip"
    assert got[2][1]["beta.txt"] == b"B" and got[2][0][0]["member"] == "beta.txt"


def test_without_a_notes_list_the_unmapped_set_is_said_on_stderr(capsys):
    blobs = [zipped([("note.txt", note(1))]), zipped([("note.txt", note(2))])]
    run.split_sets(attempt(["evidence.zip"] * 2, ["note.txt"] * 3), blobs)
    err = capsys.readouterr().err
    assert err.count("NOTE set ") == 3 and "set 3: no delivery is proven to be its own" in err


def test_the_set_pool_names_the_reason_too():
    blobs = [zipped([("note.txt", note(1))]), zipped([("note.txt", note(2))])]
    att = attempt(["evidence.zip"] * 2, [f"delivery {k}: evidence.zip -> note.txt" for k in (1, 2, 3)])
    sets = run.split_sets(att, blobs, [], [])
    solver, errors = Sha(), []
    raw, timed_out, _ = setpool.solve(solver, sets, None, errors)
    assert raw == {"set1.sha256": sha(note(1)), "set2.sha256": sha(note(2))} and solver.calls == [1, 2]
    assert len(errors) == 1 and "set 3: no delivery is proven to be its own (its questions name delivery 3" in errors[0]
    # a delivery that was mapped but not downloaded keeps its own message
    sets = run.split_sets(att, [blobs[0], b""], [], [])
    errors = []
    setpool.solve(Sha(), sets, None, errors)
    assert any(e == "set 2: its delivery was not downloaded, so it was not solved" for e in errors)


def test_an_unmapped_set_stays_an_error_after_a_second_pass_finishes_the_cut_ones():
    """Row 256 + B-042: when a second pass finishes every set the first pass cut, the cut lines become
    NOTEs, but a set that had no delivery (not downloaded, or unmapped by the split) is still unsolved
    and stays an error, with the split's reason."""
    blobs = [zipped([("note.txt", note(1))]), zipped([("note.txt", note(2))])]
    att = attempt(["evidence.zip"] * 2, [f"delivery {k}: evidence.zip -> note.txt" for k in (1, 2, 3)])
    errors = []
    run.solve_all(Sha(), run.split_sets(att, [blobs[0], b""], [], []), None, errors)
    assert len(errors) == 2       # set 2 not downloaded, set 3 unmapped: the lines the runner writes
    cut = errors + ["set 1: solver stopped after its 0.40s share with 0 answer(s) ready",
                    "set 4: the time budget was spent before it, so it was not solved",
                    "set 5: solver raised; its partial answers are used\nTraceback (most recent call last): ..."]
    kept, noted = run.fold_cut_lines(cut)
    assert kept == errors
    assert kept[1].startswith("set 3: no delivery is proven to be its own (its questions name delivery 3")
    assert noted == ["first pass: set 1: solver stopped after its 0.40s share with 0 answer(s) ready",
                     "first pass: set 4: the time budget was spent before it, so it was not solved",
                     "first pass: set 5: solver raised; its partial answers are used"]


def _timed_ladder_solve():
    """solvers/script-analysis/timed_ladder.py's serial `solve`, compiled alone: the module itself
    needs the archived Game Master client (gm, judge, lanes, ...) and stops at import without it. The
    function's own globals are the stdlib, `is_blank`, `run` (tools/run.py) and `ctf_deliveries`."""
    import ast
    import contextlib
    import signal
    import time
    import traceback
    from ctf import deliveries
    src = (ROOT / "solvers" / "script-analysis" / "timed_ladder.py").read_text()
    tree = ast.parse(src)
    wanted = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ("solve", "is_blank")]
    assert sorted(node.name for node in wanted) == ["is_blank", "solve"]
    ns = {"io": io, "time": time, "contextlib": contextlib, "traceback": traceback, "signal": signal, "run": run}
    for node in tree.body:     # the module's own binding of ctf.deliveries, whatever it names it
        if isinstance(node, ast.ImportFrom) and node.module == "ctf":
            for alias in node.names:
                if alias.name == "deliveries":
                    ns[alias.asname or alias.name] = deliveries
    exec(compile(ast.Module(body=wanted, type_ignores=[]), "timed_ladder.py", "exec"), ns)
    return ns["solve"]


def test_the_huntress_timed_runners_serial_path_names_the_reason_too():
    solve = _timed_ladder_solve()
    blobs = [zipped([("note.txt", note(1))]), zipped([("note.txt", note(2))])]
    att = attempt(["evidence.zip"] * 2, [f"delivery {k}: evidence.zip -> note.txt" for k in (1, 2, 3)])
    solver, errors = Sha(), []
    raw, timed_out, _ = solve(solver, run.split_sets(att, [blobs[0], b""], [], []), None, errors)
    assert raw == {"set1.sha256": sha(note(1))} and not timed_out and solver.calls == [1]
    assert len(errors) == 2 and errors[0] == "set 2: its delivery was not downloaded, so it was not solved"
    assert errors[1].startswith("set 3: no delivery is proven to be its own (its questions name delivery 3")


# --------------------------------------------------------------------------- the saved attempts (corpus)

def test_every_saved_mastery_pairs_each_set_with_a_delivery_of_its_own():
    """Every saved multi-set attempt of a past event: no set is unmapped and no two sets share a
    delivery or a bundle member. Not run without $CTF_REAL_CHALLENGES (read only, through ctf.paths)."""
    from ctf import deliveries as D
    from ctf import paths
    real = paths.saved_challenges_root()
    if real is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    found = sorted(real.glob("day-*/*/mastery/attempt.json")) + sorted(real.glob("day-*/*/mastery/history/*/attempt.json"))
    if not found:
        pytest.skip(f"no saved Mastery attempt found under {real}")
    checked, unsaved, rules = 0, 0, set()
    for p in found:
        try:
            saved = D.read_attempt(p)
        except D.DeliveryError as e:
            assert "is not saved at" in str(e) or "holds 0 files" in str(e), f"{p.parent.name}: {e}"
            unsaved += 1            # an attempt whose deliveries were never downloaded
            continue
        inputs = D.set_inputs(saved)
        if len(inputs) < 2:
            continue
        where = "/".join(p.parts[-4:-1])
        assert all(i.choice.mapped for i in inputs), f"{where}: {[i.label for i in inputs if not i.choice.mapped][:3]}"
        own = [(i.choice.index, i.choice.member) for i in inputs]
        assert len(set(own)) == len(own), f"{where}: two sets read one delivery"
        rules |= {i.choice.rule for i in inputs}
        checked += 1
    assert checked, f"no multi-set attempt was readable under {real} ({unsaved} without their deliveries)"
    assert rules <= {D.NAMED, D.POSITION, D.MEMBER}
