#!/usr/bin/env python3
"""B-094: numeric / symbolic encoding decoder pack (solvers/warmups/numsym.py).

Unit tests drive each decoder on a SYNTHETIC fixture built inside the test (no real challenge
files). Integration tests confirm the deterministic readers surface a flag through
crib_decode's search. Each behaviour has a test that fails when the behaviour is wrong (no
tautologies): the decoders are checked against the exact bytes they must produce, the math
constants against their known digits, and the parser against prose it must refuse.
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# crib_decode needs an event for its flag format; csctf recognises the `flag{...}` prefix.
os.environ.setdefault("CTF_EVENT", "csctf")
os.environ["CTF_TESTING"] = "1"
os.environ.setdefault("CTF_WORKDIR", tempfile.mkdtemp(prefix="test_numsym_"))
os.environ.setdefault("CTF_PLATFORM_URL", "http://127.0.0.1:9/")
os.environ.pop("CTF_TOKEN", None)
for _p in (REPO, REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import numsym as NS  # noqa: E402


# -- integer parsing -------------------------------------------------------------------------
def test_parse_ints_reads_a_number_list():
    assert NS.parse_ints(b"84 53 16 8 28") == [84, 53, 16, 8, 28]
    assert NS.parse_ints(b"[72, 73, 33]") == [72, 73, 33]
    assert NS.parse_ints(b"0x48 0x49") == [0x48, 0x49]


def test_parse_ints_refuses_prose_with_a_number():
    # A sentence that merely contains a number is not a number list.
    assert NS.parse_ints(b"I counted 3 cats and 4 dogs today") is None
    assert NS.parse_ints(b"flag{not_numbers}") is None
    assert NS.parse_ints(b"") is None


def test_parse_ints_refuses_a_single_number():
    # A lone number is not a number *list*: a decoder needs at least two tokens to
    # mean anything, so parse_ints requires >= 2 tokens. This pins the min-token
    # guard (len(tokens) < 2); relaxing it to < 1 would let "72" through as [72].
    assert NS.parse_ints(b"72") is None
    assert NS.parse_ints(b"   0x48   ") is None
    assert NS.parse_ints(b"[65]") is None
    # ...while two tokens is the smallest accepted list.
    assert NS.parse_ints(b"72 73") == [72, 73]


# -- atomic numbers -> element symbols -------------------------------------------------------
def test_atomic_decode_matches_the_periodic_table():
    # Spooky "I-D0nt-Feel-S0-G00d" arm numbers -> POISON IS NaCN (case preserved).
    assert NS.atomic_decode([84, 53, 16, 8, 28, 16, 11, 6, 7]) == "PoISONiSNaCN"
    assert NS.atomic_decode([1]) == "H"
    assert NS.atomic_decode([118]) == "Og"


def test_atomic_decode_refuses_a_non_element():
    assert NS.atomic_decode([0]) is None       # no element 0
    assert NS.atomic_decode([119]) is None      # past Oganesson
    assert NS.atomic_decode([]) is None


# -- numeric-ASCII with offset / stride / reversal auto-detect -------------------------------
def _encode_alt(text, delta=13):
    """Inverse of the Numerophobia transform: the forward int stream that the decoder turns back
    into `text` by reversing it and subtracting `delta` from the odd indices of the reversed
    stream."""
    p = [ord(c) for c in text]
    rev_stream = [(p[i] + delta if i % 2 else p[i]) for i in range(len(p))]
    return list(reversed(rev_stream))


def test_numascii_reversed_alternating_offset():
    # The exact Spooky Numerophobia shape: reversed + alternating +13 on the odd indices.
    values = _encode_alt("flag{alt_offset_13}", 13)
    hits = dict(NS.numascii_search(values))
    assert "flag{alt_offset_13}" in hits.values()
    # Pin the phase label: _encode_alt added +13 at the ODD indices of the reversed stream, so
    # the decoder must subtract at odd indices -> the winning name is exactly `rev,odd-13`. If the
    # even/odd selector were inverted, the same flag would surface under `rev,even-13` instead, so
    # asserting the exact name (not just that the flag appears) fixes the phase-label semantics.
    name = next(n for n, t in NS.numascii_search(values) if t == "flag{alt_offset_13}")
    assert name == "numascii:rev,odd-13"
    blob = " ".join(map(str, values)).encode()
    assert NS.step_fn(name)(blob).decode() == "flag{alt_offset_13}"


def test_apply_numascii_phase_selects_the_right_indices():
    # _apply_numascii's phase selects WHICH positions get `delta` subtracted: 'even' only the
    # even indices (0, 2, 4, ...), 'odd' only the odd ones. This drives the bytes directly (no
    # search, no self-consistent replay to hide behind), so inverting the selector changes the
    # output and this test fails.
    vals = [100, 100, 100, 100]
    assert NS._apply_numascii(vals, "fwd", "even", 10) == "".join(map(chr, [90, 100, 90, 100]))
    assert NS._apply_numascii(vals, "fwd", "odd", 10) == "".join(map(chr, [100, 90, 100, 90]))
    # Reversal happens before the phase selection, so the indices are counted on the reversed
    # stream; an asymmetric list pins that order too.
    assert NS._apply_numascii([100, 200], "rev", "even", 10) == "".join(map(chr, [190, 100]))


def test_numascii_plain_is_the_codepoint_reading():
    # A bare list of code points (incl. values > 255) maps straight through chr().
    values = [ord(c) for c in "flag{☃}"]   # includes U+2603 SNOWMAN
    assert NS.numascii_plain(values) == "flag{☃}"


def test_numascii_refuses_when_no_offset_makes_a_flag():
    # A list whose values are all below '{' (123): no subtraction can reach a brace, so no flag
    # shape is reachable and the self-gated search yields nothing.
    assert NS.numascii_search([72, 73, 74, 75, 76]) == []


def test_numascii_refuses_a_control_char_decode():
    # _clean_ascii is the module's stated real signature against false positives: the correct
    # offset decodes the WHOLE blob to printable ASCII. This list's ONLY flag-shaped reading
    # (fwd, delta 0) carries a control byte (0x01) inside the braces -- the broad brace shape
    # alone would accept it, so without the _clean_ascii gate the search would surface a bogus
    # "flag". The gate must refuse it, leaving the search empty. (The body is two characters:
    # the shape, flagfmt.BRACE_TEXT, takes no shorter one.)
    control = [102, 108, 97, 103, 123, 111, 1, 125]      # -> "flag{o\x01}"
    assert NS._apply_numascii(control, "fwd", "all", 0) == "flag{o\x01}"
    assert NS._looks_flag("flag{o\x01}")                 # shape gate alone would pass it
    assert not NS._clean_ascii("flag{o\x01}")            # but it is not clean printable ASCII
    assert NS.numascii_search(control) == []             # so the search excludes it
    # Swapping the sole control byte for a printable one makes the SAME offset fire: the exclusion
    # is about cleanliness, not shape or offset. If _clean_ascii always returned True, the control
    # decode above would fire too and the `== []` assertion would fail.
    clean = [102, 108, 97, 103, 123, 111, 107, 125]      # -> "flag{ok}"
    assert ("numascii:fwd,all+0", "flag{ok}") in NS.numascii_search(clean)


# -- the flag-shape gate is ctf.flagfmt's (this module compiles no flag regex of its own) -----
def test_flag_gate_is_the_flagfmt_brace_shape():
    from ctf import flagfmt
    for text in ("flag{ok}", "see PINK{That_Pie_Was_Yummy!} here", "0x41 spooky{b00}", "a\x01Zz{..}"):
        assert NS._looks_flag(text), text
        assert flagfmt.BRACE_TEXT.search(text)          # the gate fires only inside the shared shape
    # What the shared shape refuses, the gate refuses: a one-character body, a prefix glued to the
    # digit or underscore before it (the text forms keep a left word boundary), a body that spans
    # a line, a nested brace, a prefix that does not start with a letter, and an empty body.
    for text in ("flag{o}", "42flag{ok}", "_flag{ok}", "flag{a\nb}", "flag{a{b}", "1337{ok}", "{ok}", "flag{}"):
        assert not NS._looks_flag(text), text
        assert not flagfmt.BRACE_TEXT.search(text)


def test_flag_gate_never_counts_css():
    # The broad shape sees a style rule; the gate must not (flagfmt.css_like), or a decode that
    # happens to be CSS would be marked FLAG-SHAPED and would fan the search.
    from ctf import flagfmt
    assert flagfmt.BRACE_TEXT.search("btn{color:red}")
    assert not NS._looks_flag("btn{color:red}")
    assert not NS._looks_flag("<style>.btn{color:red} body{margin:0;padding:0}</style>")
    # The filter is per token: a real flag beside the CSS still counts, and a colon body that is
    # not a CSS declaration is still a flag shape.
    assert NS._looks_flag("btn{color:red} flag{ok}")
    assert NS._looks_flag("btn{colour:red}")
    # In the search: the reading that IS the style rule (forward, no offset) never fires, while the
    # same list with a non-CSS body fires it. (Other offsets of the CSS list are different decodes,
    # not CSS, and are the search's to weigh: only the CSS reading itself is the look-alike.)
    css = [ord(c) for c in "btn{color:red}"]
    not_css = [ord(c) for c in "btn{colour:red}"]
    assert "numascii:fwd,all+0" not in dict(NS.numascii_search(css))
    assert "btn{color:red}" not in dict(NS.numascii_search(css)).values()
    assert NS.numascii_search(not_css) == [("numascii:fwd,all+0", "btn{colour:red}")]
    blob = " ".join(map(str, css)).encode()
    assert b"btn{color:red}" not in [raw for _name, raw in NS.steps(blob)]


# -- routing: the manifest's keyword route (a numbers-only input has no file magic to route on) --
def test_numsym_is_routed_by_what_the_description_calls_the_encoding():
    from ctf.engines import router
    for desc in ("The lab left a list of ATOMIC NUMBERS on the whiteboard",
                 "These look like ASCII codes, but shifted",
                 "Take the digits of pi as your key"):
        hits = {h.manifest.id: h for h in router.route("misc", desc)}
        assert "warmups.numsym" in hits, desc
        assert hits["warmups.numsym"].priority == 60 and "keyword" in hits["warmups.numsym"].reason
    # No keyword, no route: the engine claims no category, so other text never routes it.
    for cat in ("misc", "crypto", "stego"):
        assert "warmups.numsym" not in {h.manifest.id for h in router.route(cat, "decode the attached image")}


# -- smooth-integer / divisor (common factor) ------------------------------------------------
def test_smooth_reduce_strips_the_common_factor():
    # Pink 31 "Suspicious Numbers": GCD 1337, quotients are atomic numbers.
    pink31 = [120330, 70861, 21392, 70861, 21392]
    g, quo = NS.smooth_reduce(pink31)
    assert g == 1337
    assert quo == [90, 53, 16, 53, 16]
    assert NS.atomic_decode(quo) == "ThISIS"


def test_smooth_reduce_none_when_coprime():
    assert NS.smooth_reduce([6, 10, 15]) is None   # gcd 1


# -- math-constant digit keystreams (computed in-repo) ---------------------------------------
def test_constant_digits_are_correct():
    assert NS.const_digits("pi", 11) == "31415926535"
    assert NS.const_digits("e", 11) == "27182818284"
    assert NS.const_digits("phi", 11) == "16180339887"


def test_mathkey_recovers_a_pi_keystream_flag():
    flag = b"flag{pi_ok}"
    ks = NS._keystream("pi", 3, 7, len(flag))
    cipher = bytes((f ^ k) & 0xFF for f, k in zip(flag, ks)).hex().encode()
    hits = dict(NS.mathkey_search(cipher, maxoff=32))
    assert "flag{pi_ok}" in hits.values()


def test_mathkey_deep_offset_matches_pink18():
    # The real Pink 18 ciphertext: pi digits, triplets mod 256, XOR, offset 1338.
    cipher = "73665d1406069b625aa34884e219d0c2ec5bf3957acb92ffde"
    hits = dict(NS.mathkey_search(cipher, maxoff=1400))
    assert hits.get("mathkey:pi,3,xor,1338") == "PINK{That_Pie_Was_Yummy!}"


def test_mathkey_name_replays():
    cipher = "73665d1406069b625aa34884e219d0c2ec5bf3957acb92ffde".encode()
    fn = NS.step_fn("mathkey:pi,3,xor,1338")
    assert fn(cipher).decode() == "PINK{That_Pie_Was_Yummy!}"


# -- crib-locked ROT-N leetspeak -------------------------------------------------------------
def test_leetrot_finds_the_shift():
    # Spooky "I-D0nt-Feel" class: ROT-10 on letters, digits are leet markers left alone.
    plain = "flag{p0150n_15_b46}"
    leet = NS._rot_letters(plain, -10).encode()   # the challenge text
    hits = dict(NS.leetrot_search(leet))
    assert hits.get("leetrot:10") == plain


def test_un_leet_table():
    assert NS.un_leet("h3ll0_w0rld") == "hello_world"
    assert NS.un_leet("1337", one_is="l") == "leet"


# -- emoji readers ---------------------------------------------------------------------------
def test_emoji_acrostic_first_letter_of_name():
    # Pink 8: first letter of each emoji's Unicode name (PURSE, IZAKAYA LANTERN, NUT AND BOLT, KIMONO).
    assert NS.emoji_acrostic("\U0001F45B\U0001F3EE\U0001F529\U0001F458") == "PINK"


def test_emoji_acrostic_none_without_enough_emoji():
    assert NS.emoji_acrostic("abc \U0001F600") is None   # fewer than 4 emoji


def test_emoji_line_diff_finds_insertions():
    # A repeated baseline line with one emoji inserted on two lines; the diff must recover two
    # inserted symbols (the mapping to letters is unsure, so we check the count, not the text).
    base = "\U0001F436\U0001F431\U0001F42D"   # dog cat mouse
    lines = [base, base + "\U0001F34B", base, base + "\U0001F418", base]  # +lemon, +elephant
    cands = NS.emoji_line_diff("\n".join(lines))
    assert cands and len(cands[0]) == 2   # two insertions recovered


def test_emoji_line_diff_is_candidate_only():
    # No repeated structure -> no candidate (never a plain answer; emit only on real repetition).
    assert NS.emoji_line_diff("\U0001F436 one line only") == []


# -- integration with crib_decode (the deterministic readers surface a flag) ------------------
def _flag_hunt(blob):
    import time
    import crib_decode as C
    # The deadline is wall-clock (crib_decode's search budget). It is not what these tests check, so it
    # is set far beyond what the search needs (a fraction of a second of CPU) so that a machine at a
    # load average over 100 cannot cut the search short; the hunt returns when its readings are done,
    # it does not wait for the deadline.
    return [f for f, _chain, _text in C._flag_hunt(blob, None, time.perf_counter() + 600)]


def test_crib_decode_surfaces_numascii_flag():
    values = _encode_alt("flag{stride_decoded}", 13)
    blob = " ".join(map(str, values)).encode()
    assert "flag{stride_decoded}" in _flag_hunt(blob)


def test_crib_decode_surfaces_mathkey_flag():
    flag = b"flag{keystream_ok}"
    ks = NS._keystream("e", 2, 3, len(flag))   # e digits, pairs, shallow offset
    cipher = bytes((f ^ k) & 0xFF for f, k in zip(flag, ks)).hex().encode()
    assert "flag{keystream_ok}" in _flag_hunt(cipher)


def test_numsym_is_optional_for_crib_decode():
    # The wiring is guarded: crib_decode imports numsym under try/except, so a tree without it
    # still runs. We assert the hook points exist and dispatch our names.
    import crib_decode as C
    assert C.NS is not None
    assert C._step_fn("numascii:rev,odd-13") is not None
    assert C._step_fn("mathkey:pi,3,xor,5") is not None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
