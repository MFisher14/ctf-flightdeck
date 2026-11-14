"""B-042: the binary speed path (speedrun/solvers/binary_par.py) pairs sets with deliveries by the
runner's own rule, ctf.deliveries.choose, or hands the attempt back to the serial path.

It used to keep its own copy of the old pairing: `delivery N` searched for anywhere in a set's FIRST
question only, else the set's place in the list. Each case below is checked against tools/run.py's
split_sets on the same synthetic attempt: where the split gives a set delivery i, the speed path does
too, and where the split leaves a set unmapped (or gives one set every delivery), the speed path
declines the attempt."""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

from speedrun.solvers import binary_par

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import run  # noqa: E402  (tools/run.py: shaped and split_sets import without the Game Master client)


def zipped(tag):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("d12.bin", date_time=(2026, 10, 1, 0, 0, 0)), f"delivery {tag}".encode())
    return buf.getvalue()


def attempt(per_set: dict, count: int) -> dict:
    """`per_set` = {set no: [artifact text of each question]}; set 0 is an attempt without sets."""
    qs = []
    for n, texts in per_set.items():
        for j, text in enumerate(texts):
            qs.append({"id": f"set{n}.q{j}" if n else f"q{j}", "question": "?", "artifact": text})
    return {"questions": qs, "answer_ids": [q["id"] for q in qs],
            "artifacts": [{"filename": "evidence.zip"} for _ in range(count)]}


def shape(att):
    """binary_par._shape, without loading the shipped solver: the same run.shaped grouping."""
    groups = {}
    for q, aid in zip(att["questions"], run.answer_ids_for(att)):
        n, question = run.shaped(q, aid)
        groups.setdefault(n, []).append(question)
    return [(n, groups[n]) for n in sorted(groups)]


def pairs(per_set, count):
    att = attempt(per_set, count)
    got = binary_par.pairing(shape(att), count)
    return att, got if got is None else [(n, i) for n, i, _ in got]


def split_pairs(att, count):
    """The split's own answer: [(set, delivery index)], or None when it leaves a set unmapped or hands
    one set every delivery (cases the speed path does not take)."""
    blobs = [zipped(k) for k in range(count)]
    out = []
    for n, _, files, ctx in run.split_sets(att, blobs, [], []):
        if "delivery_unmapped" in ctx:
            return None
        read = {v for v in files.values() if isinstance(v, bytes) and v.startswith(b"delivery ")}
        if len(read) > 1:
            return None          # the set reads every delivery
        hits = [k for k, b in enumerate(blobs) if ctx["delivery"] is b]
        assert len(hits) == 1 and read == {f"delivery {hits[0]}".encode()}
        out.append((n, hits[0]))
    return out


CASES = [
    # (sets and their questions' artifact text, deliveries, the pairing the speed path must give)
    pytest.param({1: ["delivery 2: evidence.zip -> d12.bin"], 2: ["delivery 1: evidence.zip -> d12.bin"]}, 2,
                 [(1, 1), (2, 0)], id="named-against-set-order"),
    pytest.param({1: ["evidence.zip -> d12.bin", "delivery 2: evidence.zip -> d12.bin"],
                  2: ["delivery 1: evidence.zip -> d12.bin"]}, 2,
                 [(1, 1), (2, 0)], id="named-by-a-later-question"),
    pytest.param({1: ["evidence.zip -> notes on delivery 2: d12.bin"], 2: ["evidence.zip -> d12.bin"]}, 2,
                 [(1, 0), (2, 1)], id="delivery-word-not-at-the-start"),
    pytest.param({1: ["d12.bin"], 3: ["d12.bin"]}, 2, None, id="sets-that-do-not-pair-one-to-one"),
    pytest.param({1: ["delivery 1: evidence.zip -> d12.bin", "delivery 2: evidence.zip -> d12.bin"],
                  2: ["d12.bin"]}, 2, None, id="a-set-naming-two-deliveries"),
    pytest.param({1: ["d12.bin"], 2: ["d12.bin"], 3: ["d12.bin"]}, 2, None, id="more-sets-than-deliveries"),
    pytest.param({1: ["d12.bin"], 2: ["d12.bin"]}, 2, [(1, 0), (2, 1)], id="set-order"),
    pytest.param({1: ["d12.bin"], 2: ["delivery 3: evidence.zip -> d12.bin"]}, 2, None, id="a-delivery-it-lacks"),
    pytest.param({0: ["d12.bin"]}, 1, [(0, 0)], id="no-sets-one-delivery"),
    pytest.param({1: ["delivery 2: evidence.zip -> d12.bin"]}, 2, [(1, 1)], id="one-set-naming-one"),
    pytest.param({1: ["d12.bin"]}, 2, None, id="one-set-over-every-delivery"),
]


@pytest.mark.parametrize("per_set, count, want", CASES)
def test_the_speed_path_pairs_as_the_runners_split_does(per_set, count, want):
    att, got = pairs(per_set, count)
    assert got == want
    assert got == split_pairs(att, count)


def test_the_speed_path_declines_a_bundle_and_an_attempt_without_deliveries():
    # one bundle for several sets: its members need the runner's expander, so the serial path takes it
    assert pairs({1: ["mastery.zip -> evidence-01.zip"], 2: ["mastery.zip -> evidence-02.zip"]}, 1)[1] is None
    assert pairs({0: ["d12.bin"]}, 0)[1] is None
    assert pairs({0: ["d12.bin"]}, 2)[1] is None
