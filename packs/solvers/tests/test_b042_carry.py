"""B-042: the Huntress Mastery fix the spec names as already landed in the source repo is in this tree.

The spec's blocker cites the day-walk floor (Huntress improvements row 314): a 16-record cumulative
Warmups Mastery cuts the sentence into pieces of about seven characters, and the quoted-text reader's
ten-character floor ended the walk at record 9 in every set. Inside the day walk the floor is lifted,
because there the chain is the one the record's own day proves; outside it the floor stays. The decoder
is carried code (solvers/warmups/crib_decode.py); this pins the rule so a later fold cannot drop it."""
from __future__ import annotations

import crib_decode as C

PIECE = b'"xact a"'            # a Mastery record piece: six characters between the quotes


def test_the_quoted_text_floor_is_lifted_inside_the_day_walk_only():
    assert C.d_unquote(PIECE) is None, "outside the walk a short quoted text is not a reading"
    C._walking(True)
    try:
        assert C.d_unquote(PIECE) == b"xact a"
        assert C.d_unquote(b'""') is None, "an empty quoted text is no record, in the walk either"
    finally:
        C._walking(False)
    assert C.d_unquote(PIECE) is None, "the flag is taken down after the walk"
    assert C.d_unquote(b'"ten chars!"') == b"ten chars!", "the floor outside the walk is ten characters"


def test_the_walk_flag_reaches_the_readers_that_keep_floors_of_their_own():
    """formats_more.py and the other reader module keep their own floors; the walk raises their flag too."""
    flags = [m.WALKING for m in (C.M, C.BO) if m is not None and isinstance(getattr(m, "WALKING", None), list)]
    assert flags, "no reader module with a walk flag was loaded"
    C._walking(True)
    try:
        assert C._WALKING == [True] and all(f == [True] for f in flags)
    finally:
        C._walking(False)
    assert C._WALKING == [False] and all(f == [False] for f in flags)
