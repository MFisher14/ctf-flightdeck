#!/usr/bin/env python3
"""Day 31 Script: an unsure one-copy file path yields only an unsure truth-bearing leaf."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "script-analysis"))

import labels  # noqa: E402
import day23_fold as fold  # noqa: E402

QID = "polyglot-finale-abcdef-path-leaf"
SIBLING = "polyglot-finale-abcdef-file-path"
PATH = "/tmp/.finale-31.stage"
LEAF = ".finale-31.stage"


def parsed(value):
    got = labels.parse(value)
    assert got is not None, value
    return got


def test_unwrapped_candidate():
    cur = {SIBLING: labels.unsure("script.file_path/zz31.one_copy", [("as_read", PATH)])}
    got = fold._one_copy_leaf(cur, QID, "zz31")
    p = parsed(got)
    assert p.key == "script.path_leaf/zz31.one_copy_leaf", p
    assert p.options == [("last_segment_of_as_read", LEAF)], p


def test_refusal_guards():
    one = labels.unsure("script.file_path/zz31.one_copy", [("as_read", PATH)])
    wrong_shape = labels.unsure("script.file_path/zz31.one_copy_wrapped", [("as_read", PATH)])
    many = labels.unsure("script.file_path/zz31.one_copy", [("as_read", PATH), ("other", "/x/y")])
    assert fold._one_copy_leaf({SIBLING: one}, QID, "zz31", wrapped=True) is None
    assert fold._one_copy_leaf({SIBLING: wrong_shape}, QID, "zz31") is None
    assert fold._one_copy_leaf({SIBLING: many}, QID, "zz31") is None
    assert fold._one_copy_leaf({SIBLING: PATH}, QID, "zz31") is None


def test_patch_integration_and_plain_stability():
    q = {"qid": QID, "id": QID, "question": "What is the last path segment?",
         "answer_format": {"kind": "exact_text"}}
    unsure_path = labels.unsure("script.file_path/zz31.one_copy", [("as_read", PATH)])
    got = fold.patch("finale.zz31", [q], {SIBLING: unsure_path}, {"finale.zz31": b"ordinary text"})
    p = parsed(got[QID])
    assert p.key == "script.path_leaf/zz31.one_copy_leaf" and p.options[0][1] == LEAF, p

    # The already-judged route from a plain sibling is unchanged and must not be demoted by this fix.
    stable = fold.patch("finale.zz31", [q], {SIBLING: PATH}, {"finale.zz31": b"ordinary text"})[QID]
    assert stable == LEAF, stable


if __name__ == "__main__":
    tests = (test_unwrapped_candidate, test_refusal_guards, test_patch_integration_and_plain_stability)
    for test in tests:
        test()
        print("pass", test.__name__)
    print(f"day31 script one-copy leaf: {len(tests)} passed")
