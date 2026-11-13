#!/usr/bin/env python3
"""B-055: Chef bowl-semantics conformance, and the two carried Chef readers agree.

  .venv/bin/python -m pytest tests/test_b055_chef_conformance.py

The master carried Chef twice: solvers/warmups/esolang_more.py (`chef`, the fuller reader -- loops,
baking dishes, liquefy-contents) and solvers/warmups/esolang2.py (`d_chef`, the warmup crib-gated
subset wired into crib_decode). esolang_more's roll was off by one (a Stir of 1 was a no-op), the
"duplicated interpreter with a bug" B-055 names. This battery fixes esolang_more as the canonical
master Chef and pins both readers to David Morgan-Mar's Chef spec on the bowl operations, so the two
now produce the same bytes. Each expected value is derived from the spec, not from either reader.

No physical single-copy merge is done here: the two feed different registries and each has its own
shipped test battery, so merging them is deferred (see docs/build-log/B-055.md); conformance is the
dedup guarantee -- any future fold must keep these vectors green.
"""
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "warmups"))

import esolang2        # noqa: E402
import esolang_more    # noqa: E402

READERS = {"esolang_more.chef": esolang_more.chef, "esolang2.d_chef": esolang2.d_chef}

POUR = "Pour contents of the mixing bowl into the baking dish."


def recipe(ingredients, method):
    return ("Conformance Soup.\n\nIngredients.\n" + ingredients + "\n\nMethod.\n"
            + method + "\n\nServes 1.\n").encode()


# (name, ingredients, method-before-pour, expected output bytes). Expected derived from the Chef spec.
VECTORS = [
    # Put pushes the ingredient value; a dry number prints as its decimal text.
    ("put-dry", "7 g a", "Put a into the mixing bowl.", b"7"),
    # Add / Remove / Combine / Divide act on the top of the bowl with the ingredient value.
    ("add", "10 g a\n5 g b", "Put a into the mixing bowl. Add b to the mixing bowl.", b"15"),
    ("remove", "10 g a\n3 g b", "Put a into the mixing bowl. Remove b from the mixing bowl.", b"7"),
    ("combine", "2 g a\n3 g b", "Put a into the mixing bowl. Combine b into the mixing bowl.", b"6"),
    ("divide", "20 g a\n4 g b", "Put a into the mixing bowl. Divide b into the mixing bowl.", b"5"),
    # Add dry ingredients: sum of every DRY ingredient's value (the liquid is excluded).
    ("add-dry", "2 g a\n3 g b\n65 ml c", "Add dry ingredients.", b"5"),
    # Fold pops the bowl top into an ingredient; putting it back shows the folded value.
    ("fold", "72 g a\n0 g b",
     "Put a into the mixing bowl. Fold b into the mixing bowl. Put b into the mixing bowl.", b"72"),
    # Liquefy marks an ingredient liquid, so it prints as the character of its code point.
    ("liquefy", "72 g a", "Liquefy a. Put a into the mixing bowl.", b"H"),
    # Pour is LIFO: the top of the bowl is printed first. Two liquids 65/66 -> 'B' then 'A'.
    ("pour-lifo", "65 ml a\n66 ml b",
     "Put a into the mixing bowl. Put b into the mixing bowl.", b"BA"),
    # Stir ("roll"): the top ingredient goes down N places. [1,2,3] stir 1 -> [1,3,2]; LIFO -> "231".
    ("stir-1", "1 g a\n2 g b\n3 g c",
     "Put a into the mixing bowl. Put b into the mixing bowl. Put c into the mixing bowl. "
     "Stir the mixing bowl for 1 minutes.", b"231"),
    # [1,2,3] stir 2 -> [3,1,2]; LIFO -> "213" (the regression the off-by-one hid).
    ("stir-2", "1 g a\n2 g b\n3 g c",
     "Put a into the mixing bowl. Put b into the mixing bowl. Put c into the mixing bowl. "
     "Stir the mixing bowl for 2 minutes.", b"213"),
]


@pytest.mark.parametrize("reader_name", list(READERS))
@pytest.mark.parametrize("name,ing,method,expected", VECTORS, ids=[v[0] for v in VECTORS])
def test_chef_spec_bowl_semantics(reader_name, name, ing, method, expected):
    reader = READERS[reader_name]
    got = reader(recipe(ing, method + " " + POUR))
    assert got == expected, f"{reader_name} {name}: got {got!r}, want {expected!r}"


def test_both_readers_agree_on_every_vector():
    # The dedup guarantee: the canonical reader and the crib subset produce identical bytes.
    for name, ing, method, _ in VECTORS:
        r = recipe(ing, method + " " + POUR)
        a = esolang_more.chef(r)
        b = esolang2.d_chef(r)
        assert a == b, f"{name}: esolang_more={a!r} != esolang2={b!r}"


def test_stir_of_one_is_not_a_noop():
    # Direct guard on the fixed off-by-one: a Stir of 1 must change a 2-item bowl's print order.
    r = recipe("1 g a\n2 g b",
               "Put a into the mixing bowl. Put b into the mixing bowl. "
               "Stir the mixing bowl for 1 minutes. " + POUR)
    # [1,2] stir 1 -> [2,1]; LIFO print -> "12" (unstirred would be "21").
    assert esolang_more.chef(r) == b"12"
    assert esolang2.d_chef(r) == b"12"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
