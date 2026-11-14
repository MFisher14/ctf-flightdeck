"""Numbered-record blobs through the codec graph: readings at the true cut and N-record consensus (B-163).

The sets are built here, Warmups-Mastery style: a known crib sentence and a slug answer, cut into
pieces, each piece encoded by its own (independent) encoder, written as `NN<TAB>payload` lines.
"""
from __future__ import annotations

import base64

import pytest

from ctf.codec import SlugOracle
from ctf.codec import records as R

CRIB = b"Nice work decoding this warmup! Submit this answer: "
ORACLE = SlugOracle(crib=CRIB)

MORSE = {"0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
         "7": "--...", "8": "---..", "9": "----.", "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".",
         "f": "..-."}


def rot47(b):
    return bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in b)


def caesar(b, n):
    return bytes((c - 97 + n) % 26 + 97 if 97 <= c <= 122 else (c - 65 + n) % 26 + 65 if 65 <= c <= 90 else c
                 for c in b)


def morse_hex(b):
    return " ".join(MORSE[c] for c in b.hex()).encode()


def bacon_hex(b):
    return " ".join(format(int(c, 16), "05b").replace("0", "a").replace("1", "b") for c in b.hex()).encode()


def b64(b):
    return base64.b64encode(b)


def hexs(b):
    return b.hex().encode()


def blob(text: bytes, sizes, encoders) -> bytes:
    pieces, p = [], 0
    for s in sizes:
        pieces.append(text[p:p + s])
        p += s
    pieces.append(text[p:])
    assert len(pieces) == len(encoders)
    return b"\n".join(b"%02d\t%s" % (i + 1, enc(pc)) for i, (pc, enc) in enumerate(zip(pieces, encoders)))


# --------------------------------------------------------------------------- parse

def test_parse_orders_records_and_refuses_what_is_not_records():
    recs = R.parse(b"02\tbbb\n01\taaa\n\n")
    assert [(r.index, r.payload) for r in recs] == [(1, b"aaa"), (2, b"bbb")]
    with pytest.raises(R.RecordsError, match="twice"):
        R.parse(b"01\ta\n01\tb\n")
    with pytest.raises(R.RecordsError, match="not a numbered record"):
        R.parse(b"01\ta\njust text\n")
    with pytest.raises(R.RecordsError, match="fewer than two"):
        R.parse(b"01\ta\n")


# --------------------------------------------------------------------------- the true cut

ENC6 = [b64, hexs, rot47, morse_hex, bacon_hex, b64]


def test_a_slug_split_over_three_records_assembles_at_the_true_cut():
    # The slug's last word is cut over records 4, 5 and 6 (the Day 15 shape): each piece is a fragment
    # of a word, never a word, and only the join at the right offsets reads.
    slug = b"amber-cobalt-violet-42"
    text = CRIB + slug
    data = blob(text, (20, 20, len(CRIB) - 40 + 15, 3, 2), ENC6)
    res = R.assemble(R.parse(data), ORACLE, crib=CRIB)
    assert res.answer == "amber-cobalt-violet-42", res.to_json()
    a = res.assemblies[0]
    assert [c for _, c in a.picks][:2] == [("b64",), ("hex",)]
    assert a.picks[3][1] == ("morse", "hex") and a.picks[4][1] == ("baconhex", "hex")


def test_a_short_rot47_record_inside_the_crib_is_vouched_at_its_cut():
    # A 7-character rot47 piece cannot prove itself as a sentence; at its true offset the crib does.
    text = CRIB + b"sunny-castle-opal-96"
    data = blob(text, (30, 7), [b64, rot47, hexs])
    res = R.assemble(R.parse(data), ORACLE, crib=CRIB)
    assert res.answer == "sunny-castle-opal-96"
    assert res.assemblies[0].picks[1][1] == ("rot47",) and res.assemblies[0].vouched[1]


def test_a_wrong_crib_assembles_nothing():
    data = blob(CRIB + b"amber-cobalt-violet-42", (20, 20), [b64, hexs, b64])
    res = R.assemble(R.parse(data), ORACLE, crib=b"Something else entirely, not the sentence here: ")
    assert res.answer is None and not res.assemblies and "no join" in res.reason


# --------------------------------------------------------------------------- unvouched -> consensus

CONS_ENC = [b64, hexs, rot47, b64, lambda b: caesar(b, 3), b64]


def _cons_set(slug: bytes, in_crib: bool) -> bytes:
    """Six records, record 5 is caesar-3. in_crib: record 5 holds crib text (vouched); else it lies wholly
    inside the slug, where all 25 shifts of its letters fit the slug's letters."""
    n = len(CRIB)
    if in_crib:
        sizes = (12, 12, 12, n - 36 - 10, 10)            # record 5 = the crib's last 10 characters
    else:
        sizes = (12, 12, 12, n - 36, 5)                  # record 5 = the slug's first 5 letters
    return blob(CRIB + slug, sizes, CONS_ENC)


def test_a_caesar_record_wholly_inside_the_slug_is_unvouched_not_guessed():
    # Read plain (`dpehu`) or under any of the 25 shifts, the piece fits the slug's letters: nothing proves
    # one of them, so the set has no answer and names the record, instead of returning `dpehu-cobalt-...`.
    res = R.assemble(R.parse(_cons_set(b"amber-cobalt-violet-42", in_crib=False)), ORACLE, crib=CRIB)
    assert res.answer is None and res.assemblies == []
    assert res.unvouched == [5]
    assert "unproved" in res.reason


def test_the_same_record_in_the_crib_is_vouched_by_it():
    res = R.assemble(R.parse(_cons_set(b"amber-cobalt-violet-42", in_crib=True)), ORACLE, crib=CRIB)
    assert res.answer == "amber-cobalt-violet-42"
    assert res.assemblies[0].picks[4][1] == ("caesar3",) and res.assemblies[0].vouched[4]


def test_n_record_consensus_settles_the_unvouched_record():
    sets = [R.parse(_cons_set(s, True)) for s in (b"quiet-harbor-maple-17", b"sunny-castle-opal-96",
                                                  b"waterfall-ember-fig-03")]
    sets.append(R.parse(_cons_set(b"amber-cobalt-violet-42", in_crib=False)))
    out = R.consensus(sets, ORACLE, crib=CRIB, min_n=3)
    assert [r.answer for r in out] == ["quiet-harbor-maple-17", "sunny-castle-opal-96", "waterfall-ember-fig-03",
                                       "amber-cobalt-violet-42"]
    assert out[3].consensus == {5: ("caesar3",)}
    assert "consensus" in out[3].reason


def test_consensus_needs_min_n_sets_to_agree():
    sets = [R.parse(_cons_set(s, True)) for s in (b"quiet-harbor-maple-17", b"sunny-castle-opal-96")]
    sets.append(R.parse(_cons_set(b"amber-cobalt-violet-42", in_crib=False)))
    out = R.consensus(sets, ORACLE, crib=CRIB, min_n=3)     # only two sets vouch for record 5
    assert out[2].answer is None and "no consensus chain" in out[2].reason
    ok = R.consensus(sets, ORACLE, crib=CRIB, min_n=2)
    assert ok[2].answer == "amber-cobalt-violet-42"


def test_consensus_with_rival_chains_settles_nothing():
    # Record 5 is caesar-3 in two sets and caesar-5 in two others: a tie is no consensus.
    alt = list(CONS_ENC)
    alt[4] = lambda b: caesar(b, 5)
    n = len(CRIB)

    def mk(slug, enc):
        return R.parse(blob(CRIB + slug, (12, 12, 12, n - 46, 10), enc))
    sets = [mk(b"quiet-harbor-maple-17", CONS_ENC), mk(b"sunny-castle-opal-96", CONS_ENC),
            mk(b"waterfall-ember-fig-03", alt), mk(b"lucky-otter-crane-55", alt),
            R.parse(_cons_set(b"amber-cobalt-violet-42", in_crib=False))]
    out = R.consensus(sets, ORACLE, crib=CRIB, min_n=2)
    assert [r.answer for r in out[:4]] == ["quiet-harbor-maple-17", "sunny-castle-opal-96",
                                           "waterfall-ember-fig-03", "lucky-otter-crane-55"]
    assert out[4].answer is None


def test_group_all_reads_one_single_encoding_blob():
    # Every record caesar-3: the crib records vouch for the chain, the slug-only records take it.
    n = len(CRIB)
    enc = [lambda b: caesar(b, 3)] * 6
    data = blob(CRIB + b"amber-cobalt-violet-42", (12, 12, 12, n - 36, 6), enc)
    assert R.assemble(R.parse(data), ORACLE, crib=CRIB).answer is None
    res = R.solve_blob(data, ORACLE, crib=CRIB, group_all=True)
    assert res.answer == "amber-cobalt-violet-42" and res.consensus


def test_bad_options_fail_loudly():
    recs = R.parse(b"01\ta\n02\tb\n")
    with pytest.raises(R.RecordsError):
        R.consensus([recs], ORACLE, group="nope")
    with pytest.raises(R.RecordsError):
        R.consensus([recs], ORACLE, min_n=0)
    with pytest.raises(R.RecordsError):
        R.assemble(recs, ORACLE, pin=0)


def test_a_loose_reading_with_too_little_crib_is_not_vouched():
    # Record 2 (caesar-3) holds the crib's last two characters (": ", which a shift leaves alone) and the
    # slug's first word: two crib characters prove no shift, so no join is admissible.
    n = len(CRIB)
    data = blob(CRIB + b"amber-cobalt-violet-42", (n - 2, 7), [b64, lambda b: caesar(b, 3), b64])
    res = R.assemble(R.parse(data), ORACLE, crib=CRIB)
    assert res.answer is None and res.assemblies == [] and res.unvouched == [2]


def test_a_join_must_cover_the_whole_crib():
    # A recognizer that accepts any text: two records that stop inside the crib are still no answer.
    from ctf.codec import Recognizer
    data = blob(CRIB[:30], (15,), [b64, hexs])
    res = R.assemble(R.parse(data), Recognizer(lambda d: d.decode()), crib=CRIB)
    assert res.answer is None and res.assemblies == []
    whole = R.assemble(R.parse(blob(CRIB, (25,), [b64, hexs])), Recognizer(lambda d: d.decode()), crib=CRIB)
    assert whole.answer == CRIB.decode()


def test_only_crib_vouched_records_vote():
    # Group "all" over two sets. Set A: two caesar-3 records in the crib (vouched) and three base64 records
    # in the slug (proved by base64, not vouched by the crib). Set B: caesar-3 throughout, its slug records
    # unprovable. Counting A's base64 picks as votes would tie caesar3 3-3 and settle nothing.
    n = len(CRIB)

    def c3(b):
        return caesar(b, 3)
    a = R.parse(blob(CRIB + b"quiet-harbor-maple-17", (30, n - 30, 6, 7), [c3, c3, b64, b64, b64]))
    b = R.parse(blob(CRIB + b"amber-cobalt-violet-42", (n, 6), [c3, c3, c3]))
    out = R.consensus([a, b], ORACLE, crib=CRIB, min_n=3, group="all")
    assert out[0].answer == "quiet-harbor-maple-17"
    assert out[1].answer == "amber-cobalt-violet-42" and set(out[1].consensus.values()) == {("caesar3",)}


@pytest.mark.parametrize("k,pin,vouched", [(3, R.PIN, False), (4, R.PIN, True), (3, 3, True)])
def test_the_pin_boundary_a_loose_reading_past_the_crib_needs_pin_crib_characters(k, pin, vouched):
    # Record 2 (caesar-3) holds the crib's last k characters ("r: " or "er: ") and the slug's first word.
    # With PIN = 4, three crib characters vouch for no shift and four do; pin=3 lowers the bar to three.
    assert R.PIN == 4
    n = len(CRIB)
    data = blob(CRIB + b"amber-cobalt-violet-42", (n - k, k + 6), [b64, lambda b: caesar(b, 3), b64])
    res = R.assemble(R.parse(data), ORACLE, crib=CRIB, pin=pin)
    if vouched:
        assert res.answer == "amber-cobalt-violet-42"
        assert res.assemblies[0].picks[1][1] == ("caesar3",) and res.assemblies[0].vouched[1]
    else:
        assert res.answer is None and res.assemblies == [] and res.unvouched == [2]
