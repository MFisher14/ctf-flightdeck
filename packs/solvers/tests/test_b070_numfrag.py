"""B-070: numbered flag fragments (ctf/numfrag.py): pieces that carry their own position, joined by it."""
import pytest

from ctf import event, flagfmt, numfrag

SPOOKY = flagfmt.for_profile(event.load("spooky"))
CSCTF = flagfmt.for_profile(event.load("csctf"))
HUNTRESS = flagfmt.for_profile(event.load("huntress"))

DEMENTED = [
    ("deleted/f7c00b3/retrospective.c", "int main(void) { return 0; }\n"
                                        "// miss the days when people cared ...spooky{the_g00d_ (1)\n"),
    (".fog61.fog (hex-decoded)", "the_l0st_@nd (2)"),
    ("git directory file errored_space.txt", "61, the year the memories cuts through the fog... th3_void} (3)\n"),
]


@pytest.mark.parametrize("line,index,total,body", [
    ("the_l0st_@nd (2)", 2, None, "the_l0st_@nd"),
    ("the_l0st_@nd(2)", 2, None, "the_l0st_@nd"),
    ("abc_def [2/3]", 2, 3, "abc_def"),
    ("abc_def (part 2 of 3)", 2, 3, "abc_def"),
    ("(2) abc_def", 2, None, "abc_def"),
    ("[2/3]: abc_def", 2, 3, "abc_def"),
    ("part 2: abc_def", 2, None, "abc_def"),
    ("Fragment #2 of 3 = abc_def", 2, 3, "abc_def"),
    ("flag part 2 - abc_def", 2, None, "abc_def"),
    ("2: abc_def", 2, None, "abc_def"),
    ("2) abc_def", 2, None, "abc_def"),
    ("   trailing space kept out (10)  \r", 10, None, "trailing space kept out"),
])
def test_every_position_form_is_read(line, index, total, body):
    got = numfrag.find([("src", line)])
    assert [(f.index, f.total, f.body, f.origin) for f in got] == [(index, total, body, "src")]


@pytest.mark.parametrize("line", [
    "a plain line with no position",
    "12:30 meeting in the fog",            # a time, not "12: text"
    "2024: the year",                      # more than two digits
    "value (100)",                         # a position past two digits
    "value (65)",                          # one past MAX_INDEX
    "(2)",                                 # a position and no text
    "x" * (numfrag.MAX_LINE - 3) + " (2)",  # one byte over MAX_LINE
    "",
])
def test_lines_that_carry_no_position_are_not_fragments(line):
    assert numfrag.find([("src", line)]) == []


def test_find_reads_bytes_dedupes_a_piece_seen_twice_and_is_bounded(monkeypatch):
    got = numfrag.find([("a", b"abc (1)\nabc (1)\n"), ("b", "abc (1)"), ("c", "abd (1)")])
    assert [(f.body, f.origin) for f in got] == [("abc", "a"), ("abd", "c")]
    monkeypatch.setattr(numfrag, "MAX_FRAGMENTS", 3)
    assert len(numfrag.find([("a", "\n".join(f"p{i} ({i % 60})" for i in range(50)))])) == 3
    monkeypatch.setattr(numfrag, "MAX_LINES", 2)
    assert [f.body for f in numfrag.find([("a", "x (1)\ny (2)\nz (3)")])] == ["x", "y"]


def test_demented_memories_joins_by_position_and_ranks_the_repaired_spelling_first():
    frags = numfrag.find(DEMENTED, SPOOKY)
    assert [f.index for f in frags] == [1, 2, 3]
    joins = numfrag.assemble(frags, SPOOKY)
    assert [j.flag for j in joins] == ["spooky{the_g00d_the_l0st_@nd_th3_void}",     # the one the platform took
                                       "spooky{the_g00d_the_l0st_@ndth3_void}"]      # as written: rejected
    repaired, literal = joins
    assert [p.text for p in literal.parts] == ["spooky{the_g00d_", "the_l0st_@nd", "th3_void}"]
    assert [p.name for p in literal.parts] == ["(1) deleted/f7c00b3/retrospective.c", "(2) .fog61.fog (hex-decoded)",
                                               "(3) git directory file errored_space.txt"]
    assert all(p.container == "numbered" for p in literal.parts)
    assert repaired.parts[:3] == literal.parts and "separator '_' put back at 1 boundary" in repaired.parts[3].name


def test_the_order_of_the_texts_does_not_matter_the_positions_do():
    joins = numfrag.assemble(numfrag.find(list(reversed(DEMENTED)), SPOOKY), SPOOKY)
    assert joins[0].flag == "spooky{the_g00d_the_l0st_@nd_th3_void}"


def test_the_literal_join_stays_first_when_no_boundary_shows_the_separator():
    frags = numfrag.find([("a", "note: CSCTF{ab_cd (1)"), ("b", "ef_gh} (2)")])
    assert [j.flag for j in numfrag.assemble(frags, CSCTF)] == ["CSCTF{ab_cdef_gh}", "CSCTF{ab_cd_ef_gh}"]


def test_a_body_with_no_separator_gives_the_literal_join_only():
    frags = numfrag.find([("a", "CSCTF{abc (1)"), ("b", "def (2)"), ("c", "ghi} (3)")])
    assert [j.flag for j in numfrag.assemble(frags, CSCTF)] == ["CSCTF{abcdefghi}"]


def test_a_separator_is_never_put_next_to_a_brace():
    frags = numfrag.find([("a", "CSCTF{ (1)"), ("b", "a_b (2)"), ("c", "} (3)")])
    assert [j.flag for j in numfrag.assemble(frags, CSCTF)] == ["CSCTF{a_b}"]


def test_zero_based_positions_join_too():
    frags = numfrag.find([("a", "(0) CSCTF{zero"), ("b", "(1) _based}")])
    assert [j.flag for j in numfrag.assemble(frags, CSCTF)] == ["CSCTF{zero_based}"]


@pytest.mark.parametrize("texts", [
    [("a", "CSCTF{abc (1)"), ("c", "ghi} (3)")],                       # position 2 is missing
    [("a", "CSCTF{abc (2)"), ("b", "def} (3)")],                       # does not start at 0 or 1
    [("a", "abc (1)"), ("b", "def} (2)")],                             # nothing opens a flag
    [("a", "CSCTF{abc (1)"), ("b", "def (2)")],                        # nothing closes it
    [("a", "CSCTF{abc (1)")],                                          # one piece is not a join
    [("a", "NOPE{abc (1)"), ("b", "def} (2)")],                        # not this event's prefix
    [("a", "CSCTF{abc (1/3)"), ("b", "def} (2/3)")],                   # "of 3" was said and 3 is not there
    [("a", "CSCTF{abc (1)"), ("b", "see CSCTF{whole} (2)")],           # the last piece is a whole flag, not a tail
    [("a", "CSCTF{a (1)"), ("b", "b{c (2)"), ("c", "d} (3)")],         # a middle piece with a brace in it
    [("a", "CSCTF{abc (1)"), ("b", "two words (here), (2)"), ("c", "ghi} (3)")],   # a middle with no usable word
])
def test_sets_that_cannot_be_a_flag_give_nothing(texts):
    assert numfrag.assemble(numfrag.find(texts), CSCTF) == []


def test_a_stated_total_that_is_met_joins():
    frags = numfrag.find([("a", "CSCTF{abc (1/3)"), ("b", "def (2/3)"), ("c", "ghi} (3/3)")])
    assert [j.flag for j in numfrag.assemble(frags, CSCTF)] == ["CSCTF{abcdefghi}"]


def test_the_join_must_fit_the_events_flag_format():
    texts = [("a", "flag{0123456789abcdef (1)"), ("b", "0123456789abcdef} (2)")]
    assert [j.flag for j in numfrag.assemble(numfrag.find(texts), HUNTRESS)] == ["flag{0123456789abcdef0123456789abcdef}"]
    texts = [("a", "flag{0123456789abcdef (1)"), ("b", "not_hex_at_all} (2)")]
    assert numfrag.assemble(numfrag.find(texts), HUNTRESS) == []


def test_a_middle_piece_in_prose_gives_its_last_word_and_a_closing_piece_its_closing_word():
    texts = [("a", "start CSCTF{one_ (1)"), ("b", "the middle is two_ (2)"), ("c", "and it ends three} trailing (3)")]
    joins = numfrag.assemble(numfrag.find(texts), CSCTF)
    assert joins[0].flag == "CSCTF{one_two_three}"
    assert [p.text for p in joins[0].parts] == ["CSCTF{one_", "two_", "three}"]


def test_decoy_pieces_for_one_position_give_every_combination_capped(monkeypatch):
    texts = [("a", "CSCTF{a (1)"), ("b", "b1 (2)"), ("c", "b2 (2)"), ("d", "c} (3)")]
    assert [j.flag for j in numfrag.assemble(numfrag.find(texts), CSCTF)] == ["CSCTF{ab1c}", "CSCTF{ab2c}"]
    monkeypatch.setattr(numfrag, "MAX_JOINS", 1)
    assert [j.flag for j in numfrag.assemble(numfrag.find(texts), CSCTF)] == ["CSCTF{ab1c}"]
    monkeypatch.setattr(numfrag, "MAX_PER_INDEX", 1)
    monkeypatch.setattr(numfrag, "MAX_JOINS", 12)
    assert [j.flag for j in numfrag.assemble(numfrag.find(texts), CSCTF)] == ["CSCTF{ab1c}"]


def test_a_shorter_run_is_used_when_the_longest_has_no_closing_piece():
    texts = [("a", "CSCTF{ab (1)"), ("b", "cd} (2)"), ("c", "unrelated list item (3)")]
    assert [j.flag for j in numfrag.assemble(numfrag.find(texts), CSCTF)] == ["CSCTF{abcd}"]
