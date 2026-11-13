"""B-232: the answer-format renderer (ctf/answerfmt/): contract reading, list order and join axes,
batch rendering, multi-file synthesis by answer-id suffix, the labels wire and shell word reading.

Every fixture is synthetic. The shapes are the coverage rows the item closes: Huntress Day 6 (steps sent
comma-joined although the format said `>`), Day 15 (OOXML relationship targets in file order when the
judge took sorted; the timed `synthesis-sha256-order` question), Day 23 (zip member names in file order
when the judge took ascending)."""
from __future__ import annotations

import hashlib
import json

import pytest

from ctf import cli
from ctf.answerfmt import (MAX_OPTIONS, OPTIONS, PLAIN, WITHHELD, AnswerFormatError, read, render,
                           render_answers)
from ctf.answerfmt import shellword, synth, wire

STEPS = {"kind": "ordered_tokens", "syntax": "exact tokens joined by > with no surrounding spaces or explanatory text"}


# ------------------------------------------------------------------------------------------- contract

@pytest.mark.parametrize("syntax, sep, tight", [
    ("exact tokens joined by > with no surrounding spaces", ">", True),
    ("tokens separated with -> between them", "->", False),
    ("tokens joined by >.", ">", False),
    ('steps joined by " > " in order', " > ", False),
    ("comma-separated names, no spaces", ",", True),
    ("names separated by commas", ",", False),
    ("names separated by a comma followed by a space", ", ", False),
    ("one per line", "\n", False),
    ("pipe-delimited values", "|", False),
    ("the value as written", None, False),
])
def test_contract_reads_the_stated_separator(syntax, sep, tight):
    c = read({"kind": "exact_text", "syntax": syntax})
    assert c.separator == sep
    assert c.tight is tight


def test_contract_two_different_separators_are_a_conflict_not_a_pick():
    c = read({"kind": "exact_text", "syntax": "joined by > and separated by commas"})
    assert c.separator is None
    assert any(x.startswith("separator:") for x in c.conflicts)


@pytest.mark.parametrize("syntax, order", [
    ("a JSON array in ascending order", "ascending"),
    ("names sorted alphabetically", "ascending"),
    ("values in sorted order", "ascending"),
    ("in descending order", "descending"),
    ("names in file order", "file"),
    ("member names in central-directory order", "file"),
    ("in the order they appear in the archive", "file"),
    ("values not sorted", "file"),
    ("as stored", "file"),
    ("in any order", "any"),
    ("names sorted by size", "keyed"),
    ("filenames in ascending digest order", "keyed"),
    ("names sorted by filename", "ascending"),
    ("the sorted names", None),          # bare 'sorted' states no order
    ("tokens of alphabetical characters [a-z]", None),     # an element's form, not the list's order
    ("names in alphabetical order", "ascending"),
    ("comma-separated", None),
])
def test_contract_reads_the_stated_order(syntax, order):
    assert read({"kind": "exact_text", "syntax": syntax}).order == order


def test_contract_order_conflict_between_syntax_and_question_keeps_the_axis():
    c = read({"kind": "exact_text", "syntax": "comma-separated, ascending order"},
             question_text="List the targets in the order they appear in the file.")
    assert c.order is None
    assert c.conflicts == ("order: ascending / file",)
    r = render(["b", "a"], {"kind": "exact_text", "syntax": "comma-separated, ascending order, no spaces"},
               question_text="List the targets in the order they appear in the file.")
    assert r.status == OPTIONS and r.axes == ("order",)


def test_contract_reads_the_order_from_the_question_text():
    c = read({"kind": "exact_text", "syntax": "comma-separated"}, question_text="Give them in ascending order.")
    assert c.order == "ascending"


@pytest.mark.parametrize("fmt, container", [
    ({"kind": "json", "syntax": "a compact JSON array"}, "json_array"),
    ({"kind": "json", "syntax": "a JSON object"}, "json_object"),
    ({"kind": "json", "syntax": "a JSON object or JSON array"}, "json"),
    ({"kind": "json"}, "json"),
    ({"kind": "exact_text", "syntax": "a JSON array of strings"}, "json_array"),
    ({"kind": "exact_text", "syntax": "plain text"}, None),
])
def test_contract_container(fmt, container):
    assert read(fmt).container == container


def test_contract_literal_none_permission_and_accepted_values():
    c = read({"kind": "integer", "syntax": "base-10 integer; use the literal none only when absent"})
    assert c.none_ok is True
    assert read({"kind": "integer", "syntax": "base-10 integer"}).none_ok is False
    e = read({"kind": "enum", "accepted_values": ["Low", "High", 3], "normalization": "case_insensitive"})
    assert e.accepted == ("Low", "High", "3") and e.case_insensitive


def test_contract_absent_and_malformed():
    c = read(None)
    assert c.present is False and c.kind == "" and c.separator is None
    with pytest.raises(AnswerFormatError, match="not a mapping"):
        read(["kind", "json"])


# ------------------------------------------------------------------------------------------- Day 6

DAY6_LISTS = [["decode", "drop", "persist"], ["fetch", "xor", "exec"], ["read", "b64", "write", "run"],
              ["env", "probe", "beacon"], ["unpack", "stage", "launch"], ["gather", "post"]]


@pytest.mark.parametrize("given", ["list", "gt", "gt_spaced"])
def test_day6_new_language_day_every_step_list_takes_the_stated_separator(given):
    """A new-language day: the reader hands its step lists as a list or split on the stated mark; every
    one must go out joined by `>` as the contract states, plain. Fails if any answer ignores the separator."""
    shapes = {"list": lambda t: t, "gt": ">".join, "gt_spaced": " > ".join}
    for toks in DAY6_LISTS:
        r = render(shapes[given](toks), STEPS)
        assert r.status == PLAIN, (given, toks, r)
        assert r.value == ">".join(toks)


@pytest.mark.parametrize("given, mark, name", [("comma", ",", "split_comma"), ("arrow", "->", "split_arrow"),
                                               ("pipe", " | ", "split_pipe")])
def test_day6_steps_on_an_unstated_separator_are_rejoined_but_offered_beside_the_whole(given, mark, name):
    """The Day 6 shape (steps comma-joined under `joined by >`): the `>` rejoin comes first, but `a,b`
    may also be one token holding a comma, so it is never sent plain."""
    for toks in DAY6_LISTS:
        r = render(mark.join(toks), STEPS)
        assert r.status == OPTIONS and r.axes == ("split",), r
        assert r.options == ((f"{name}+given+stated", ">".join(toks)), ("whole", mark.join(toks).strip()))


def test_a_token_holding_another_mark_splits_only_on_the_stated_separator():
    r = render("cut -d, -f1>sort", STEPS)
    assert (r.status, r.value) == (PLAIN, "cut -d, -f1>sort")
    url = {"kind": "exact_text", "syntax": "URLs joined by | with no spaces, in file order"}
    r = render("https://a.example/x,y|https://b.example/", url)
    assert (r.status, r.value) == (PLAIN, "https://a.example/x,y|https://b.example/")
    # the stated `|` absent: a single URL holding a comma is offered whole, not only split
    r = render("https://a.example/x,y", url)
    assert r.status == OPTIONS and dict(r.options)["whole"] == "https://a.example/x,y"
    # `->` holds `>` but is not the stated `>`: the tokens are `a->b` and `c` (not `a-`, `b`, `c`), and a
    # token holding the separator cannot be joined by it
    r = render("a->b>c", STEPS)
    assert r.status == WITHHELD and "contains the separator '>'" in r.reason


def test_several_unstated_separators_or_an_empty_token_are_withheld():
    r = render("a,b|c", STEPS)
    assert r.status == WITHHELD and "several list separators" in r.reason and "'>'" in r.reason
    comma = {"kind": "exact_text", "syntax": "comma-separated, no spaces"}
    r = render("a,,b", comma)
    assert r.status == WITHHELD and "empty token" in r.reason
    assert render("a>b>", STEPS).status == WITHHELD
    assert render("a,b", comma).value == "a,b"       # control: the same contract renders a sound list


def test_day6_tokens_keep_their_order_under_ordered_tokens():
    r = render(["z", "a", "m"], STEPS)
    assert r.value == "z>a>m"     # the sequence is the fact: no ascending option, ever


def test_steps_with_spacing_unstated_offer_tight_then_spaced():
    r = render(["a", "b"], {"kind": "ordered_tokens", "syntax": "tokens joined by >"})
    assert r.status == OPTIONS and r.axes == ("join",)
    assert r.options == (("given+tight", "a>b"), ("given+spaced", "a > b"))


def test_quoted_separator_keeps_its_blanks_and_is_plain():
    r = render(["a", "b", "c"], {"kind": "ordered_tokens", "syntax": 'tokens joined by " > "'})
    assert (r.status, r.value) == (PLAIN, "a > b > c")


def test_ordered_tokens_without_a_stated_separator_never_goes_plain():
    r = render(["a", "b"], {"kind": "ordered_tokens"})
    assert r.status == OPTIONS
    assert [n for n, _ in r.options] == ["given+gt", "given+gt_spaced", "given+comma"]


# ------------------------------------------------------------------------------------------- Day 15 / Day 23

DOCX_TARGETS = ["https://z.example/t", "https://a.example/s", "file:///C:/x.dotm"]


def test_day15_list_with_order_unstated_offers_file_order_then_ascending():
    r = render(DOCX_TARGETS, {"kind": "exact_text", "syntax": "comma-separated URLs, no spaces"})
    assert r.status == OPTIONS and r.axes == ("order",)
    assert r.options == (("file_order+stated", ",".join(DOCX_TARGETS)),
                         ("ascending+stated", ",".join(sorted(DOCX_TARGETS))))


def test_day15_sorted_stated_is_plain_ascending():
    r = render(DOCX_TARGETS, {"kind": "exact_text", "syntax": "comma-separated URLs sorted alphabetically, no spaces"})
    assert (r.status, r.value) == (PLAIN, ",".join(sorted(DOCX_TARGETS)))


def test_day23_zip_member_names_json_list_gets_the_order_axis_with_code_point_ascending():
    names = ["notes/readme.txt", "MANIFEST", "a.bin", "Z.cfg"]
    r = render(names, {"kind": "json", "syntax": "a compact JSON array of member names"})
    assert r.status == OPTIONS and r.axes == ("order",)
    assert dict(r.options) == {"file_order+json": json.dumps(names, separators=(",", ":")),
                               "ascending+json": '["MANIFEST","Z.cfg","a.bin","notes/readme.txt"]'}
    assert r.options[0][0] == "file_order+json"


def test_already_ascending_list_has_no_order_axis():
    r = render(["a", "b", "c"], {"kind": "json", "syntax": "a JSON array"})
    assert (r.status, r.value) == (PLAIN, '["a","b","c"]')


def test_descending_stated():
    r = render([3, 10, 7], {"kind": "json", "syntax": "a JSON array of integers in descending order"})
    assert (r.status, r.value) == (PLAIN, "[10,7,3]")


def test_intlist_ints_sort_numerically():
    r = render([10, 9, 100], {"kind": "exact_text", "syntax": "comma-separated, no spaces, ascending"})
    assert r.value == "9,10,100"


def test_digit_strings_get_lexical_and_numeric_ascending_unless_integers_are_stated():
    r = render(["10", "9", "100"], {"kind": "exact_text", "syntax": "comma-separated, no spaces"})
    assert dict(r.options) == {"file_order+stated": "10,9,100", "ascending+stated": "10,100,9",
                               "ascending_numeric+stated": "9,10,100"}
    r = render(["10", "9", "100"], {"kind": "exact_text", "syntax": "comma-separated integers, no spaces"})
    assert dict(r.options) == {"file_order+stated": "10,9,100", "ascending+stated": "9,10,100"}


def test_comma_spacing_unstated_is_comma_space_not_space_comma_space():
    r = render(["b", "a"], {"kind": "exact_text", "syntax": "comma-separated, in file order"})
    assert r.options == (("file_order+tight", "b,a"), ("file_order+spaced", "b, a"))


def test_no_contract_list_offers_both_axes_capped_and_distinct():
    r = render(["10", "9", "100"], None)
    assert r.status == OPTIONS and r.axes == ("order", "join")
    assert len(r.options) <= MAX_OPTIONS
    assert len({v for _, v in r.options}) == len(r.options)
    assert r.options[0] == ("file_order+comma", "10,9,100")


def test_options_are_cut_at_the_cap(monkeypatch):
    from ctf.answerfmt import rendering as render_mod
    monkeypatch.setattr(render_mod, "MAX_OPTIONS", 2)
    r = render_mod.render(["b", "a"], None)
    assert [n for n, _ in r.options] == ["file_order+comma", "file_order+comma_space"]


@pytest.mark.parametrize("syntax, question, conflicts", [
    ("comma-separated, no spaces, sorted by size, largest first", None, ()),
    ("comma-separated, no spaces, ordered by timestamp, ascending", None, ()),
    ("comma-separated, no spaces, sorted by size", "Give the largest first.", ()),
    ("comma-separated, no spaces, sorted by size", "List them in the order they appear in the archive.",
     ("order: keyed / file",)),
])
def test_a_keyed_order_with_a_direction_or_another_order_stays_keyed_and_is_withheld(syntax, question, conflicts):
    """`largest first` is the key's direction, not a second order (and no conflict): reading it as a
    conflict sent ['big', 'small'] plain in file order (file order and ascending happened to agree)."""
    fmt = {"kind": "exact_text", "syntax": syntax}
    c = read(fmt, question)
    assert (c.order, c.conflicts) == ("keyed", conflicts)
    r = render(["big", "small"], fmt, question_text=question)
    assert r.status == WITHHELD and "ordered=True" in r.reason
    assert render(["big", "small"], fmt, question_text=question, ordered=True).value == "big,small"


def test_a_keyed_order_beside_file_order_names_the_conflict():
    c = read({"kind": "exact_text", "syntax": "sorted by size"}, question_text="in file order")
    assert (c.order, c.conflicts) == ("keyed", ("order: keyed / file",))
    assert read(None, "sorted by size, largest first").order == "keyed"


def test_keyed_order_is_withheld_unless_the_caller_ordered_it():
    fmt = {"kind": "exact_text", "syntax": "names sorted by size, comma-separated, no spaces"}
    r = render(["b", "a"], fmt)
    assert r.status == WITHHELD and "ordered=True" in r.reason
    r = render(["b", "a"], fmt, ordered=True)
    assert (r.status, r.value) == (PLAIN, "b,a")


@pytest.mark.parametrize("syntax, question", [
    ("comma-separated, no spaces, in ascending order of modification time", None),
    ("comma-separated, no spaces, in descending order of size", None),
    ("comma-separated, no spaces", "List them in order of size."),
    ("comma-separated, no spaces", "List the files in order of their creation time, ascending."),
    ("comma-separated, no spaces", "List them from oldest to newest."),
    ("comma-separated, no spaces", "Newest first."),
    ("comma-separated, no spaces, in chronological order", None),
    ("comma-separated, no spaces, sorted chronologically", None),
    ("comma-separated, no spaces, in reverse chronological order", None),
    ("comma-separated, no spaces, in increasing order of file size", None),
])
def test_an_order_of_key_chronology_or_age_is_keyed_and_the_name_sort_is_withheld(syntax, question):
    """`ascending order of modification time` used to read as plain `ascending`, so ['b', 'a'] went out
    plain as the name sort `a,b`; `in order of size`, `oldest to newest`, `chronological` were not read
    at all, so file order and name sort were offered. Each is a key the list cannot be sorted on here."""
    fmt = {"kind": "exact_text", "syntax": syntax}
    assert read(fmt, question).order == "keyed"
    r = render(["b", "a"], fmt, question_text=question)
    assert r.status == WITHHELD and "ordered=True" in r.reason
    assert render(["b", "a"], fmt, question_text=question, ordered=True).value == "b,a"


@pytest.mark.parametrize("syntax, order", [
    ("in the order of appearance", "file"),
    ("in order of first occurrence", "file"),
    ("in the order of the input", None),           # the list's own order is no key
    ("in order of file name", None),
    ("the order of the tokens matters", None),     # `order of` without `in` or a direction states no order
    ("in descending order of name", "descending"),
])
def test_order_of_a_noun_that_is_no_key_is_not_keyed(syntax, order):
    assert read({"kind": "exact_text", "syntax": syntax}).order == order


def test_one_per_line_is_a_stated_separator_for_a_string():
    """A newline is stated by `one per line`; `"\\n".strip()` is empty, which used to read it as
    unstated, turning a sure answer into a one-option `split` probe."""
    fmt = {"kind": "exact_text", "syntax": "one per line, in file order"}
    r = render("b\na", fmt)
    assert (r.status, r.value) == (PLAIN, "b\na")
    assert render("b\r\na\n", fmt).value == "b\na"
    r = render("b\na", {"kind": "exact_text", "syntax": "one per line"})
    assert r.status == OPTIONS and r.axes == ("order",)
    assert r.options == (("file_order+stated", "b\na"), ("ascending+stated", "a\nb"))
    # control: a newline under a stated comma is still an unstated split
    r = render("b\na", {"kind": "exact_text", "syntax": "comma-separated, no spaces, in file order"})
    assert r.status == OPTIONS and r.axes[0] == "split"


def test_a_join_an_element_contains_is_dropped():
    r = render(["a,b", "c"], {"kind": "exact_text", "syntax": "comma-separated, no spaces, in file order"})
    assert r.status == WITHHELD and "contains the separator" in r.reason
    r = render(["a b", "c"], None)
    assert "file_order+space" not in dict(r.options)
    assert "file_order+comma" in dict(r.options)


def test_empty_list_is_none_only_where_allowed():
    allowed = {"kind": "exact_text", "syntax": "comma-separated; use the literal none only when there are none"}
    assert render([], allowed).value == "none"
    r = render([], {"kind": "exact_text", "syntax": "comma-separated"})
    assert r.status == WITHHELD


def test_list_under_a_json_object_contract_and_a_set_are_withheld():
    assert render(["a"], {"kind": "json", "syntax": "a JSON object"}).status == WITHHELD
    assert render({"a", "b"}, None).status == WITHHELD


# ------------------------------------------------------------------------------------------- scalars

def test_integer_kind():
    assert render("  42 ", {"kind": "integer"}).value == "42"
    assert render(42, {"kind": "integer"}).value == "42"
    r = render("ELF64", {"kind": "integer", "syntax": "base-10 integer"})
    assert r.status == WITHHELD and "not a base-10 integer" in r.reason
    assert render("none", {"kind": "integer", "syntax": "use the literal none only when absent"}).value == "none"


def test_enum_takes_the_listed_spelling_and_withholds_an_unlisted_value():
    fmt = {"kind": "enum", "accepted_values": ["Persistence", "Execution"]}
    assert render("Execution", fmt).value == "Execution"
    r = render("persistence", fmt)
    assert (r.status, r.value, r.options[0][0]) == (PLAIN, "Persistence", "listed_spelling")
    assert render("Discovery", fmt).status == WITHHELD
    partial = {"kind": "enum", "accepted_values": ["a"], "syntax": "a tactic such as a"}
    assert render("Discovery", partial).value == "Discovery"


def test_enum_spelling_is_withheld_when_two_listed_entries_differ_only_by_case():
    fmt = {"kind": "enum", "accepted_values": ["Low", "low", "High"]}
    assert render("low", fmt).value == "low"          # an exact entry is still sent as given
    r = render("LOW", fmt)
    assert r.status == WITHHELD, r                    # 'Low' or 'low': no one listed spelling
    assert render("HIGH", fmt).value == "High"


def test_json_kind_and_mappings():
    assert render("{bad", {"kind": "json"}).status == WITHHELD
    assert render({"b": 1, "a": [2]}, {"kind": "json"}).value == '{"b":1,"a":[2]}'
    assert render({"a": 1}, {"kind": "exact_text"}).status == WITHHELD


def test_unsure_strings_and_none_are_not_rendered():
    assert render('??{"k":"metadata.x/y","o":[]}', STEPS).status == WITHHELD
    assert render(None, STEPS).status == WITHHELD


def test_booleans():
    r = render(True, {"kind": "boolean", "syntax": "true or false"})
    assert (r.status, r.value) == (PLAIN, "true")
    r = render(False, {"kind": "boolean"})
    assert r.status == OPTIONS and r.options == (("lower", "false"), ("title", "False"))


def test_plain_text_passes_unchanged():
    assert render("Hello, World", {"kind": "exact_text", "syntax": "the value as written"}).value == "Hello, World"


# ------------------------------------------------------------------------------------------- batches

def test_render_answers_sorts_each_answer_into_plain_unsure_held_and_passed():
    qs = [{"id": "s1-steps", "answer_format": STEPS},
          {"id": "zip-members", "answer_format": {"kind": "json", "syntax": "a JSON array"}},
          {"id": "count", "answer_format": {"kind": "integer"}},
          {"id": "already", "answer_format": {"kind": "exact_text"}}]
    unsure = '??{"k":"metadata.x/y","o":[["a","1"]]}'
    out = render_answers(qs, {"s1-steps": "a > b > c", "zip-members": ["b", "a"], "count": "ELF64",
                              "already": unsure, "stranger": "x"})
    assert out.plain == {"s1-steps": "a>b>c"}
    assert list(out.unsure) == ["zip-members"] and out.unsure["zip-members"].axes == ("order",)
    assert set(out.held) == {"count", "stranger"} and "unknown" in out.held["stranger"]
    assert out.passed == {"already": unsure}
    lines = out.lines()
    assert "PLAIN s1-steps: 'a>b>c'" in lines and any(x.startswith("HELD count:") for x in lines)


def test_render_answers_aligns_answer_ids_by_position_and_names_a_broken_contract():
    qs = [{"id": "q1", "answer_format": {"kind": "integer"}}]
    assert render_answers(qs, {"a-1": 7}, answer_ids=["a-1"]).plain == {"a-1": "7"}
    with pytest.raises(AnswerFormatError, match="1 answer ids for 2"):
        render_answers(qs + qs, {}, answer_ids=["a-1"])
    with pytest.raises(AnswerFormatError, match="^q1: "):
        render_answers([{"id": "q1", "answer_format": "kind=integer"}], {"q1": 1})


def test_render_answers_reads_the_order_from_the_question_text():
    qs = [{"id": "t", "question": "List them in ascending order.",
           "answer_format": {"kind": "exact_text", "syntax": "comma-separated, no spaces"}}]
    assert render_answers(qs, {"t": ["b", "a"]}).plain == {"t": "a,b"}


# ------------------------------------------------------------------------------------------- synthesis

FILES = {"a.txt": b"one", "b.jpg": b"two", "c.exe": b"three"}


def _q(algo="SHA-256", order="ascending", extra=""):
    return (f"Compute the full-file {algo} digest of each named file, then submit a compact JSON array of their "
            f"filenames in {order} digest order.{extra} Files: [\"a.txt\",\"b.jpg\",\"c.exe\"]")


def _by(algo, files=FILES, reverse=False):
    return sorted(files, key=lambda n: hashlib.new(algo, files[n]).hexdigest(), reverse=reverse)


JSON_ARRAY = {"kind": "json", "syntax": "a compact JSON array"}


def test_synth_routes_by_suffix():
    assert synth.route("metadata-day-15-synthesis-sha256-order")[0].name == "digest_order"
    assert synth.route("files-md5-order")[1].group("algo") == "md5"
    assert synth.route("x-sha3_256-digest-order")[1].group("algo") == "sha3_256"
    assert synth.route("x-sha256-order-note") is None
    assert synth.route("sha256") is None
    assert synth.route("") is None


@pytest.mark.parametrize("aid, algo, word", [("m-synthesis-sha256-order", "sha256", "SHA-256"),
                                             ("m-md5-order", "md5", "MD5"),
                                             ("m-sha3-256-order", "sha3_256", "SHA3-256"),
                                             ("m-sha1-order", "sha1", "SHA1")])
def test_synth_digest_order_ascending(aid, algo, word):
    r = synth.answer(aid, _q(word), JSON_ARRAY, FILES)
    assert r.status == PLAIN, r.reason
    assert json.loads(r.value) == _by(algo)
    # the fixture's digest order must differ from the file order, or this test proves nothing
    assert _by(algo) != list(FILES) or _by(algo, reverse=True) != list(FILES)


def test_synth_descending_and_the_contract_join():
    r = synth.answer("m-synthesis-sha256-order", _q(order="descending"), JSON_ARRAY, FILES)
    assert json.loads(r.value) == _by("sha256", reverse=True)
    joined = {"kind": "exact_text", "syntax": "file names joined by | with no spaces"}
    r = synth.answer("m-synthesis-sha256-order", _q(), joined, FILES)
    assert (r.status, r.value) == (PLAIN, "|".join(_by("sha256")))


@pytest.mark.parametrize("text, why", [
    (_q("MD5"), "names the digest"),
    (_q(extra=" Use the first 16 bytes."), "whole file"),
    (_q(order="any"), "ascending or descending"),
    ("Compute the full-file SHA-256 digest of each named file and submit a JSON array of the digests in ascending "
     "order. Files: [\"a.txt\"]", "file names"),
    ("Order the files by SHA-256 ascending and give their filenames.", "no 'Files:'"),
    ("Ascending SHA-256 order of their filenames. Files: [a.txt]", "does not parse"),
    ("Ascending SHA-256 order of their filenames. Files: [\"a.txt\", \"a.txt\"]", "more than once"),
])
def test_synth_withholds_what_the_question_does_not_settle(text, why):
    r = synth.answer("m-synthesis-sha256-order", text, JSON_ARRAY, FILES)
    assert r.status == WITHHELD and why in r.reason, r.reason
    assert synth.covered("m-synthesis-sha256-order", text, JSON_ARRAY) is not None


def test_synth_delivery_problems_are_withheld_but_covered():
    assert synth.covered("m-synthesis-sha256-order", _q(), JSON_ARRAY) is None
    r = synth.answer("m-synthesis-sha256-order", _q(), JSON_ARRAY, {"a.txt": b"1", "b.jpg": b"2"})
    assert r.status == WITHHELD and "'c.exe'" in r.reason
    same = {"a.txt": b"x", "b.jpg": b"x", "c.exe": b"y"}
    assert "share a digest" in synth.answer("m-synthesis-sha256-order", _q(), JSON_ARRAY, same).reason
    assert synth.answer("unrelated-id", _q(), JSON_ARRAY, FILES).status == WITHHELD
    assert synth.answer("m-synthesis-sha256-order", _q(), {"kind": "json", "syntax": "a JSON object"},
                        FILES).status == WITHHELD


def test_synth_covered_refuses_a_json_object_format_before_the_files_arrive():
    why = synth.covered("m-synthesis-sha256-order", _q(), {"kind": "json", "syntax": "a JSON object"})
    assert why is not None and "JSON object" in why
    assert synth.covered("m-synthesis-sha256-order", _q(), {"kind": "json", "syntax": "a JSON array"}) is None


def test_synth_matches_a_unique_basename_in_a_folder(tmp_path):
    (tmp_path / "deliv" / "sub").mkdir(parents=True)
    for n, b in FILES.items():
        (tmp_path / "deliv" / "sub" / n).write_bytes(b)
    (tmp_path / "outside.txt").write_bytes(b"secret")
    (tmp_path / "deliv" / "link.txt").symlink_to(tmp_path / "outside.txt")
    files = synth.files_from_dir(tmp_path / "deliv")
    assert set(files) == {"sub/a.txt", "sub/b.jpg", "sub/c.exe"}
    r = synth.answer("m-synthesis-sha256-order", _q(), JSON_ARRAY, files)
    assert json.loads(r.value) == _by("sha256")
    files["other/a.txt"] = b"dup"
    assert "2 delivered files are named 'a.txt'" in synth.answer("m-synthesis-sha256-order", _q(), JSON_ARRAY,
                                                                  files).reason
    with pytest.raises(synth.SynthError, match="not a directory"):
        synth.files_from_dir(tmp_path / "outside.txt")


def test_synth_register_routes_a_new_suffix_and_refuses_an_unanchored_one():
    def solve(m, text, c, files):
        return sorted(files, key=lambda n: len(files[n])), None
    try:
        synth.register("size_order_test", r"[-_]size[-_]order$", solve)
        r = synth.answer("x-size-order", "", JSON_ARRAY, {"big": b"xxxx", "small": b"x"})
        assert (r.status, r.value) == (PLAIN, '["small","big"]')
    finally:
        synth._HANDLERS.pop("size_order_test", None)
    with pytest.raises(synth.SynthError, match="anchored"):
        synth.register("bad", r"size-order", solve)


# ------------------------------------------------------------------------------------------- wire

@pytest.fixture
def labels_off(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    monkeypatch.setenv("CTF_FAMILY_PRIOR", "off")
    return wire.load_labels()


def test_wire_plain_and_withheld_need_no_labels():
    assert wire.wire({"id": "s", "answer_format": STEPS}, ["a", "b"], "script", labels=object()) == "a>b"
    assert wire.wire({"id": "n", "answer_format": {"kind": "integer"}}, "x", "binary", labels=object()) is None


def test_wire_order_axis_is_a_candidate_pick_and_join_axis_an_ordinary_pick(labels_off):
    lab = labels_off
    q = {"id": "zip-members", "answer_format": {"kind": "json", "syntax": "a JSON array"}}
    got = wire.wire(q, ["b", "a"], "metadata", labels=lab)
    parsed = lab.parse(got)
    assert lab.is_candidate(got)
    assert parsed.key == "metadata.zip-members/answer_format.json.order#candidates"
    assert parsed.options == [("file_order+json", '["b","a"]'), ("ascending+json", '["a","b"]')]
    q = {"id": "s1-steps", "answer_format": {"kind": "ordered_tokens", "syntax": "joined by >"}}
    got = wire.wire(q, ["a", "b"], "script", labels=lab)
    assert lab.is_unsure(got) and not lab.is_candidate(got)
    assert lab.parse(got).key == "script.s1-steps/answer_format.ordered_tokens.join"


def test_wire_list_with_no_contract_has_order_and_join_open_and_is_a_candidate_pick(labels_off):
    """The usual case: a list answer and no answer_format at all (a CTFd event)."""
    lab = labels_off
    got = wire.wire({"id": "members", "answer_format": None}, ["b", "a"], "metadata", labels=lab)
    assert lab.is_candidate(got), got
    parsed = lab.parse(got)
    assert parsed.key == "metadata.members/answer_format.any.order+join#candidates"
    assert parsed.options[0] == ("file_order+comma", "b,a")


def test_wire_split_axis_is_a_candidate_pick(labels_off):
    lab = labels_off
    got = wire.wire({"id": "s2-steps", "answer_format": STEPS}, "a,b", "script", labels=lab)
    assert lab.is_candidate(got), got
    assert lab.parse(got).options == [("split_comma+given+stated", "a>b"), ("whole", "a,b")]


def test_wire_goes_plain_once_the_judge_accepted_the_hypothesis(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "on")
    monkeypatch.setenv("CTF_FAMILY_PRIOR", "off")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    lab = wire.load_labels()
    q = {"id": "zip-members-b232test", "answer_format": {"kind": "json", "syntax": "a JSON array"}}
    first = wire.wire(q, ["b", "a"], "metadata", labels=lab)
    key = lab.parse(first).key
    assert lab.learn(key, "ascending+json", "accepted") is True
    # the next variant's own list, answered under the accepted hypothesis
    assert wire.wire(q, ["z", "c", "m"], "metadata", labels=lab) == '["c","m","z"]'


def test_wire_options_need_an_id():
    with pytest.raises(ValueError, match="no id"):
        wire.wire({"answer_format": {"kind": "json"}}, ["b", "a"], "metadata", labels=object())


# ------------------------------------------------------------------------------------------- shell words

@pytest.mark.parametrize("line, value", [
    ("M='ab'\"cd\"ef$'\\x67'", "abcdefg"),
    ("M='part1''part2''part3'", "part1part2part3"),
    ("export HOST_ID=\"host\"'-'\"42\"", "host-42"),
    ("M=$'\\101\\x42\\u0043\\n'", "ABC\n"),
    ("M=\"a\\\"b\\$c\"", "a\"b$c"),
    ("M=a\\ b", "a b"),
    ("M=", ""),
    ("M=\"ab\\\ncd\"", "abcd"),               # backslash-newline inside "..." is a line continuation
    ("M=$'\\777x'", "\xffx"),                 # an octal escape over 0o377 keeps its low byte (bash)
    ("M=\"pre$X\"", None),
    ("M=$(cat f)'x'", None),
    ("M=`id`", None),
])
def test_shell_assignment_concatenates_touching_pieces(line, value):
    assert shellword.assignment(line) == ("M" if line.startswith("M") else "HOST_ID", value)


def test_shell_words_split_on_blanks_and_stop_at_a_separator():
    assert shellword.words("printf '%s' 'a'\"b\"c d\\ e ; rm -rf x") == ["printf", "%s", "abc", "d e"]
    assert shellword.words("echo ${A}'x' y") == ["echo", None, "y"]
    assert shellword.assignment("echo M=1") is None


def test_shell_unterminated_quote_is_a_named_error():
    with pytest.raises(shellword.ShellWordError, match="never closes"):
        shellword.word("'abc")
    with pytest.raises(shellword.ShellWordError, match="never closes"):
        shellword.word('"abc')
    with pytest.raises(shellword.ShellWordError, match="never closes"):
        shellword.word("$(abc")


# ------------------------------------------------------------------------------------------- CLI

def test_cli_render_exit_codes(capsys):
    assert cli.main(["answer-format", "render", json.dumps(STEPS), '"a > b"']) == 0
    assert "'a>b'" in capsys.readouterr().out
    assert cli.main(["answer-format", "render", json.dumps(STEPS), '"a,b"']) == 3
    assert "split_comma+given+stated" in capsys.readouterr().out
    fmt = json.dumps({"kind": "json", "syntax": "a JSON array"})
    assert cli.main(["answer-format", "render", fmt, '["b","a"]']) == 3
    out = capsys.readouterr().out
    assert "UNSURE value" in out and "ascending+json" in out
    assert cli.main(["answer-format", "render", '{"kind":"integer"}', '"x"']) == 1
    assert cli.main(["answer-format", "render", "[1]", '"x"']) == 2
    assert "FORMAT" in capsys.readouterr().err


def test_cli_contract_and_batch(tmp_path, capsys):
    assert cli.main(["answer-format", "contract", json.dumps(STEPS), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["separator"] == ">"
    body = tmp_path / "attempt.json"
    body.write_text(json.dumps({"questions": [{"id": "q1", "answer_format": STEPS}],
                                "answer_ids": ["a1"]}))
    ans = tmp_path / "key.json"
    ans.write_text(json.dumps({"answers": {"a1": ["x", "y"]}}))
    assert cli.main(["answer-format", "batch", f"@{body}", f"@{ans}"]) == 0
    assert "ANSWER-FORMAT plain=1 unsure=0 held=0" in capsys.readouterr().out
    ans.write_text(json.dumps({"a1": ["x", "y"], "zz": 1}))
    assert cli.main(["answer-format", "batch", f"@{body}", f"@{ans}"]) == 1
    body.write_text(json.dumps({"questions": [{"id": "q1"}], "answer_ids": ["a", "b"]}))
    assert cli.main(["answer-format", "batch", f"@{body}", f"@{ans}"]) == 2
    assert cli.main(["answer-format", "batch", f"@{tmp_path / 'missing.json'}", f"@{ans}"]) == 2


def test_cli_synth(tmp_path, capsys):
    d = tmp_path / "files"
    d.mkdir()
    for n, b in FILES.items():
        (d / n).write_bytes(b)
    q = tmp_path / "q.json"
    q.write_text(json.dumps({"id": "m-synthesis-sha256-order", "question": _q(), "answer_format": JSON_ARRAY}))
    assert cli.main(["answer-format", "synth", f"@{q}", str(d), "--json"]) == 0
    assert json.loads(json.loads(capsys.readouterr().out)["value"]) == _by("sha256")
    q.write_text(json.dumps({"id": "m-synthesis-sha256-order", "question": _q("MD5"), "answer_format": JSON_ARRAY}))
    assert cli.main(["answer-format", "synth", f"@{q}", str(d)]) == 1
    assert cli.main(["answer-format", "synth", f"@{q}", str(tmp_path / "nope")]) == 2
