"""The shared recursive codec graph (B-163, ctf/codec/graph.py, ctf/codec/codecs.py).

Every fixture is built here by INDEPENDENT encoders (the stdlib, or a few lines written in this file),
never by the graph's own decoders run backwards. The matrix covers the Huntress gaps: the Binary
lane's ordered wrapper pairs (18 of 25 missed), the shared peeler's three-layer stop, and loose
transforms before, between and after two strict codecs (ROT47 plus double Base64). Nothing here
runs a challenge binary or touches the network.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import itertools
import json
import random
import struct
import time
import zlib

import pytest

from ctf import event
from ctf.codec import AnyOf, CribOracle, FlagOracle, Graph, Recognizer, SlugOracle, apply_chain, by_name
from ctf.codec import codecs as C
from ctf.codec.codecs import Codec, CodecError

CSCTF = event.load("csctf")
FLAG = "CSCTF{amber_cobalt_violet_42}"
P = f"Nice work. The answer is {FLAG} -- submit it.".encode()
ORACLE = FlagOracle(CSCTF)


# --------------------------------------------------------------------------- independent encoders

def rot47(b):
    return bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in b)


def caesar(b, n):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + n) % 26 + 65
        elif 97 <= c <= 122:
            out[i] = (c - 97 + n) % 26 + 97
    return bytes(out)


def atbash(b):
    return bytes(155 - c if 65 <= c <= 90 else 219 - c if 97 <= c <= 122 else c for c in b)


def xor(b, k):
    return bytes(c ^ k for c in b)


MORSE_ENC = {"a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.", "0": "-----", "1": ".----",
             "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..",
             "9": "----.", "t": "-", "h": "....", "o": "---", "n": "-.", "s": "...", "w": ".--", "r": ".-.",
             "k": "-.-", "g": "--.", "i": "..", "m": "--", "u": "..-", "l": ".-..", "p": ".--.", "q": "--.-",
             "v": "...-", "x": "-..-", "y": "-.--", "z": "--..", "j": ".---"}

STRICT_ENC = {
    "b64": base64.b64encode,
    "b32": base64.b32encode,
    "b85": base64.b85encode,
    "a85": lambda b: base64.a85encode(b, adobe=True),
    "hex": lambda b: b.hex().encode(),
    "zlib": zlib.compress,
    "gzip": lambda b: gzip.compress(b, mtime=0),
    "bz2": bz2.compress,
    "binary": lambda b: " ".join(format(c, "08b") for c in b).encode(),
    "url": lambda b: "".join(f"%{c:02X}" for c in b).encode(),
}
LOOSE_ENC = {
    "rot47": (rot47, "rot47"),
    "caesar7": (lambda b: caesar(b, 7), "caesar7"),
    "xor0x29": (lambda b: xor(b, 0x29), "xor0x29"),
    "rot13": (lambda b: caesar(b, 13), "rot13"),
    "atbash": (atbash, "atbash"),
    "reverse": (lambda b: b[::-1], "reverse"),
}


def enc(chain, data):
    """Encode innermost first: chain is written outermost first, as the graph reports it."""
    for name in reversed(chain):
        data = STRICT_ENC[name](data) if name in STRICT_ENC else LOOSE_ENC[name][0](data)
    return data


# --------------------------------------------------------------------------- the composition matrix

@pytest.mark.parametrize("outer,inner", list(itertools.product(sorted(STRICT_ENC), repeat=2)))
def test_every_ordered_pair_of_strict_codecs_decodes(outer, inner):
    r = Graph().search(enc((outer, inner), P), ORACLE)
    assert r.unique == FLAG, (outer, inner, r.to_json())
    assert all(h.confirmed for h in r.hits)
    assert r.truncated is None


@pytest.mark.parametrize("chain", [
    ("b64", "b64", "b64"), ("hex", "hex", "hex"), ("b32", "b32", "b32"), ("b85", "b85", "b85"),
    ("b64", "gzip", "b64"), ("hex", "b64", "zlib"), ("b32", "hex", "b85"), ("b64", "b64", "b64", "b64"),
    ("b64", "gzip", "b64", "zlib", "hex"), ("hex", "b32", "b64", "a85", "b64", "bz2"),
])
def test_repeated_and_mixed_deep_chains_decode_past_two_layers(chain):
    r = Graph().search(enc(chain, P), ORACLE)
    assert r.unique == FLAG, (chain, r.to_json())
    assert any(h.chain == chain for h in r.hits), [h.chain for h in r.hits]


LOOSE_CASES = []
for _lname in LOOSE_ENC:
    for _s1, _s2 in (("b64", "b64"), ("b64", "hex"), ("hex", "b32")):
        LOOSE_CASES += [(_lname, (_lname, _s1, _s2)), (_lname, (_s1, _lname, _s2)), (_lname, (_s1, _s2, _lname))]


@pytest.mark.parametrize("loose,chain", LOOSE_CASES, ids=["+".join(c) for _, c in LOOSE_CASES])
def test_a_loose_step_before_between_or_after_two_strict_codecs(loose, chain):
    r = Graph().search(enc(chain, P), ORACLE)
    assert r.unique == FLAG, (chain, r.to_json())
    assert r.hits[0].confirmed, "a strict step in the chain confirms it"


def test_the_u1_misses_now_decode_with_their_exact_chain():
    # the Day 30 audit's U1 table, with a flag target: each was None from the carried decoder.
    for chain in [("rot47", "b64", "b64"), ("b64", "rot47", "b64"), ("caesar7", "b64", "b64"),
                  ("b64", "xor0x29", "b64"), ("xor0x29", "b64", "b64")]:
        r = Graph().search(enc(chain, P), ORACLE)
        assert [h.chain for h in r.hits] == [chain], (chain, r.to_json())


def test_strict_only_graph_misses_loose_compositions_max_loose_zero():
    # max_loose=0 is the representation-only graph: the loose matrix above depends on loose edges.
    r = Graph(max_loose=0).search(enc(("rot47", "b64", "b64"), P), ORACLE)
    assert r.hits == []


# --------------------------------------------------------------------------- symbol alphabets over hex

def morse_hex(b):
    return " ".join(MORSE_ENC[c] for c in b.hex()).encode()


def bacon_hex(b, width=5, zero="a", one="b"):
    return " ".join(format(int(c, 16), f"0{width}b").replace("0", zero).replace("1", one) for c in b.hex()).encode()


def tap_hex(b):
    out = []
    for c in b.hex():
        v = int(c, 16)
        out.append("." * (v // 4 + 1) + " " + "." * (v % 4 + 1))
    return "  ".join(out).encode()


def poly_hex(b):
    return " ".join(f"{int(c, 16) // 4 + 1}{int(c, 16) % 4 + 1}" for c in b.hex()).encode()


@pytest.mark.parametrize("name,fn,first", [
    ("morse", morse_hex, "morse"),
    ("bacon5", bacon_hex, "baconhex"),
    ("bacon5-inverted", lambda b: bacon_hex(b, zero="b", one="a"), "baconhex"),
    ("bacon4-binary", lambda b: bacon_hex(b, 4, "0", "1"), "baconhex"),
    ("tap", tap_hex, "taphex"),
    ("polybius", poly_hex, "polyhex"),
])
def test_symbol_alphabets_over_hex(name, fn, first):
    r = Graph().search(fn(P), ORACLE)
    assert r.unique == FLAG, (name, r.to_json())
    assert any(h.chain == (first, "hex") for h in r.hits), [h.chain for h in r.hits]


def test_symbol_alphabet_over_hex_inside_base64():
    r = Graph().search(base64.b64encode(morse_hex(P)), ORACLE)
    assert r.unique == FLAG and r.hits[0].chain == ("b64", "morse", "hex")


LETTERS = "the quiet harbor at dawn"


def _bacon26(text):
    return " ".join(format(ord(c) - 97, "05b").replace("0", "a").replace("1", "b") for c in text if c != " ").encode()


def _tap_letters(text):
    sq = "abcdefghijlmnopqrstuvwxyz"
    return " / ".join("  ".join("." * (sq.index(c) // 5 + 1) + " " + "." * (sq.index(c) % 5 + 1) for c in w)
                      for w in text.split()).encode()


def _poly_letters(text):
    sq = "abcdefghiklmnopqrstuvwxyz"
    return " / ".join(" ".join(f"{sq.index(c) // 5 + 1}{sq.index(c) % 5 + 1}" for c in w) for w in text.split()).encode()


@pytest.mark.parametrize("data,crib,codec", [
    (" / ".join(" ".join(MORSE_ENC[c] for c in w) for w in LETTERS.split()).encode(), LETTERS, "morse"),
    (_bacon26(LETTERS), LETTERS.replace(" ", ""), "bacon"),
    (_tap_letters(LETTERS), LETTERS, "tap"),
    (_poly_letters(LETTERS), LETTERS, "polybius"),
])
def test_letter_symbol_alphabets(data, crib, codec):
    r = Graph().search(data, CribOracle(crib))
    assert r.unique == crib and any(h.chain == (codec,) for h in r.hits), r.to_json()


def test_run_length_groups_inside_base64():
    rle = ",".join(f"1:{chr(c)}" for c in P).encode()
    r = Graph().search(base64.b64encode(rle), ORACLE)
    assert r.unique == FLAG and r.hits[0].chain == ("b64", "runlength")


# --------------------------------------------------------------------------- keyed: rail fence + slug crib

def rail_encode(s, rails):
    rows = [[] for _ in range(rails)]
    r, step = 0, 1
    for ch in s:
        rows[r].append(ch)
        if rails > 1:
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
    return bytes(itertools.chain.from_iterable(rows))


CRIB = b"Nice work decoding this warmup! Submit this answer: "


def test_rail_fence_of_a_long_slug_reads_with_the_slug_crib():
    plain = CRIB + b"waterfall-ember-fig-03"
    for rails in (3, 7, 11):
        r = Graph().search(rail_encode(plain, rails), SlugOracle(crib=CRIB))
        assert r.unique == "waterfall-ember-fig-03", (rails, r.to_json())
        assert r.hits[0].chain == (f"rail{rails}",) and r.hits[0].confirmed, "a strong oracle confirms it"


def test_rail_fence_inside_base64_with_the_slug_crib():
    plain = CRIB + b"amber-cobalt-violet-42"
    r = Graph().search(base64.b64encode(rail_encode(plain, 5)), SlugOracle(crib=CRIB))
    assert r.unique == "amber-cobalt-violet-42" and r.hits[0].chain == ("b64", "rail5")


def test_keyed_steps_are_off_under_a_flag_shape_oracle_unless_asked():
    # A transposition can assemble a flag shape out of any text with those letters: under the flag oracle
    # the rail family is not searched by default, and is when the caller asks for it.
    data = rail_encode(P, 4)
    assert Graph().search(data, ORACLE).hits == []
    r = Graph(keyed=True).search(data, ORACLE)
    assert r.unique == FLAG and r.hits[0].chain == ("rail4",)


# --------------------------------------------------------------------------- oracles validate the final object

def _hcfg(campaign, key=0x33):
    payload = json.dumps({"campaign": campaign, "url": "https://example.invalid"}, separators=(",", ":")).encode()
    return b"HCFG" + bytes([1, key]) + struct.pack("<HI", len(payload), zlib.crc32(payload)) + xor(payload, key)


def _read_hcfg(b):
    """A CRC-validating recognizer, written like a lane's own final-object check."""
    if len(b) < 12 or not b.startswith(b"HCFG"):
        return None
    key = b[5]
    n, crc = struct.unpack("<HI", b[6:12])
    payload = xor(b[12:12 + n], key)
    if len(payload) != n or zlib.crc32(payload) != crc:
        return None
    return json.loads(payload)["campaign"]


B1 = {"b64": base64.b64encode, "b32": base64.b32encode, "b85": base64.b85encode,
      "hex": lambda d: d.hex().encode(), "zlib": zlib.compress}


@pytest.mark.parametrize("outer,inner", list(itertools.product(sorted(B1), repeat=2)))
def test_binary_lane_wrapper_pair_matrix_through_a_crc_recognizer(outer, inner):
    data = B1[outer](B1[inner](_hcfg("BR30-000")))
    r = Graph().search(data, Recognizer(_read_hcfg, "hcfg"))
    assert r.unique == "BR30-000", (outer, inner, r.to_json())
    assert r.hits[0].chain == (outer, inner)


def test_triple_base64_hcfg_and_a_corrupt_crc_is_no_answer():
    good = base64.b64encode(base64.b64encode(base64.b64encode(_hcfg("BR30-000"))))
    assert Graph().search(good, Recognizer(_read_hcfg)).unique == "BR30-000"
    bad = bytearray(_hcfg("BR30-000"))
    bad[-1] ^= 1
    r = Graph().search(base64.b64encode(base64.b64encode(bytes(bad))), Recognizer(_read_hcfg))
    assert r.hits == [], "a CRC failure is not an answer, whatever it looks like"


def test_two_distinct_answers_at_the_goal_depth_are_ambiguous():
    # Two toy representation codecs both accept the input and lead to different flags: both are reported,
    # and `unique` refuses to pick the first.
    a = Codec("toya", C.STRICT, lambda b: b"CSCTF{first}" if b == b"seed" else None)
    b = Codec("toyb", C.STRICT, lambda b: b"CSCTF{second}" if b == b"seed" else None)
    r = Graph((a, b)).search(b"seed", ORACLE)
    assert r.answers == ["CSCTF{first}", "CSCTF{second}"] and r.unique is None


def test_representation_chain_wins_over_a_shallower_loose_reading():
    # Stage one (representation steps only) is searched first: its confirmed answer stands even though a
    # loose edge reaches a different flag one step sooner.
    s1 = Codec("s1", C.STRICT, lambda b: b"mid" if b == b"seed" else None)
    s2 = Codec("s2", C.STRICT, lambda b: b"CSCTF{strict}" if b == b"mid" else None)
    lo = Codec("lo", C.LOOSE, lambda b: b"CSCTF{loose}" if b == b"seed" else None)
    r = Graph((s1, s2, lo), xor=False).search(b"seed", ORACLE)
    assert r.answers == ["CSCTF{strict}"] and r.hits[0].chain == ("s1", "s2")
    only_loose = Graph((lo,), xor=False).search(b"seed", ORACLE)
    assert only_loose.answers == ["CSCTF{loose}"] and not only_loose.hits[0].confirmed


def test_crib_and_anyof_oracles():
    data = base64.b64encode(caesar(b"attack at dawn, then " + FLAG.encode(), 3))
    assert Graph().search(data, CribOracle("attack at dawn")).unique == "attack at dawn"
    r = Graph().search(data, AnyOf(CribOracle("attack at dawn"), ORACLE))
    assert set(r.answers) == {"attack at dawn", FLAG}


def test_slug_oracle_needs_one_slug_after_the_crib():
    o = SlugOracle(crib=CRIB)
    assert o.check(CRIB + b"amber-cobalt-violet-42") == ["amber-cobalt-violet-42"]
    assert o.check(CRIB + b"Amber-cobalt-violet-42") == []
    assert o.check(b"other text amber-cobalt-violet-42") == []
    assert o.check(CRIB + b"amber-cobalt-violet-42 " + CRIB + b"quiet-harbor-maple-17") == [], "two slugs: ambiguous"
    bare = SlugOracle()
    assert bare.check(b"some sentence\namber-cobalt-violet-42\n") == ["amber-cobalt-violet-42"]
    assert bare.check(b"amber-cobalt-violet-42 is in the middle\nof text") == []


def test_flag_oracle_refuses_a_control_character_body():
    assert ORACLE.check(b"x CSCTF{ok_body} y") == ["CSCTF{ok_body}"]
    assert ORACLE.check(b"CSCTF{bad\x07body}") == []


# --------------------------------------------------------------------------- bounds, noise, errors

def test_node_bound_is_reported_not_hidden():
    r = Graph(max_nodes=30).search(enc(("rot47", "b64", "b64"), P), ORACLE)
    assert r.hits == [] and r.truncated == "nodes"


def test_deadline_bound_is_reported_and_kept():
    t = time.monotonic()
    r = Graph().search(enc(("hex", "b64", "b32", "b85"), P), ORACLE, deadline=t - 1)
    assert r.truncated == "deadline" and r.hits == []


def test_byte_bound_is_reported():
    r = Graph(max_bytes=200).search(enc(("hex", "hex", "hex"), P), ORACLE)
    assert r.truncated == "bytes"


def test_decompression_bomb_is_refused_not_inflated():
    bomb = zlib.compress(b"\x00" * (C.MAX_OUT + 4096), 9)
    assert C.d_zlib(bomb) is None
    t = time.monotonic()
    r = Graph().search(base64.b64encode(bomb), ORACLE)
    assert r.hits == [] and time.monotonic() - t < 10
    assert C.d_zlib(zlib.compress(b"\x00" * 4096)) == b"\x00" * 4096


@pytest.mark.parametrize("kind", ["b64", "hex", "binary", "letters"])
def test_noise_reaches_no_flag(kind):
    rng = random.Random(11)
    make = {"b64": lambda: base64.b64encode(rng.randbytes(1500)),
            "hex": lambda: rng.randbytes(600).hex().encode(),
            "binary": lambda: rng.randbytes(500),
            "letters": lambda: bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz {}CSTF") for _ in range(400))}[kind]
    for _ in range(25):
        r = Graph().search(make(), ORACLE, deadline=time.monotonic() + 2)
        assert r.hits == [], r.to_json()


def test_a_codec_that_raises_is_named_in_errors():
    def boom(b):
        raise RuntimeError("bad input")
    r = Graph((Codec("boom", C.STRICT, boom),)).search(b"abc", ORACLE)
    assert r.hits == [] and r.errors and r.errors[0].startswith("boom: RuntimeError")


def test_bad_bounds_and_duplicate_names_fail_loudly():
    with pytest.raises(ValueError):
        Graph(max_depth=0)
    with pytest.raises(ValueError):
        Graph(max_loose=-1)
    with pytest.raises(CodecError):
        Graph((C.CORE[0], C.CORE[0]))
    with pytest.raises(ValueError):
        Graph().search(b"x", None)


# --------------------------------------------------------------------------- codec units

def test_xor_text_keys_are_exactly_the_printable_making_keys():
    data = xor(b"Hello, World!", 0x5A)
    keys = C.xor_text_keys(data)
    assert 0x5A in keys
    for k in range(1, 256):
        printable = all(32 <= (c ^ k) < 127 or (c ^ k) in (9, 10, 13) for c in data)
        assert (k in keys) == printable, k


def test_apply_chain_and_names():
    data = enc(("b64", "rot47", "hex"), P)
    assert apply_chain(data, ("b64", "rot47", "hex")) == P
    assert apply_chain(data, ("hex",)) is None
    assert by_name("xor0x29").decode(b"A)") == bytes([0x41 ^ 0x29, 0])
    assert by_name("caesar7").decode(b"h") == b"a"
    with pytest.raises(CodecError):
        by_name("nope")
    with pytest.raises(CodecError):
        by_name("xor0x00")
    assert C.representation_steps(("rot47", "b64", "caesar3", "morse", "warmups.b91")) == ["b64", "morse", "warmups.b91"]


@pytest.mark.parametrize("codec,good,want,bad", [
    ("hex", b"de ad:be-ef", b"\xde\xad\xbe\xef", b"abc"),
    ("hex", b"0x41 0x42", b"AB", b"0x4 0x42"),
    ("b64", b"SGVs\nbG8=", b"Hello", b"SGVs bG8="),
    ("b64url", b"-_-_", base64.urlsafe_b64decode(b"-_-_"), b"abcd"),
    ("b32", b"jbswy3dp", b"Hello", b"JBSWY3D1"),
    ("b58", b"9Ajdvzr", b"Hello", b"0OIl0OIl"),
    ("a85", b"<~87cURDZ~>", b"Hello", b"<~87cUR"),
    ("binary", b"01001000 01101001", b"Hi", b"0100100 01101001"),
    ("binary", b"1001000 1101001", b"Hi", b"10010001101001"),
    ("octal", b"110 151", b"Hi", b"110 158"),
    ("decimal", b"72,105", b"Hi", b"72,300"),
    ("url", b"%48%69", b"Hi", b"no escapes"),
    ("html", b"&#72;&#x69;", b"Hi", b"plain"),
    ("runlength", b"2:a,1:,,3:b", b"aa,bbb", b"2a,3b"),
    ("utf16", "Hi there".encode("utf-16-le"), b"Hi there", b"Hi there"),
    ("morse", b".... .. / - .... . .-. .", b"hi there", b".... ..--..--.."),
])
def test_strict_codec_vectors(codec, good, want, bad):
    c = by_name(codec)
    assert c.decode(good) == want
    assert c.decode(bad) is None


def test_a_sparse_url_escape_after_a_loose_step_is_not_followed():
    # rot47 of letters makes stray `%xx` runs; a url decode of a text that is mostly not escapes is not a
    # layer, so the loose output is listed but never expanded. A dense one is.
    sparse = rot47(b"plain words with one %41 escape in a long sentence of text")
    states, _ = Graph().explore(sparse)
    assert any(ch == ("rot47",) for _, ch in states)
    assert not any(ch[:2] == ("rot47", "url") for _, ch in states)
    dense = rot47(b"%48%65%6C%6C%6F%20%74%68%65%72%65")
    states, _ = Graph().explore(dense)
    assert any(ch[:2] == ("rot47", "url") and d == b"Hello there" for d, ch in states)


def test_the_deadline_is_kept_inside_one_wide_expansion():
    # 300 slow codecs on one state: the deadline is checked while the state is expanded, not only between
    # states, so the search stops near its deadline instead of after every codec has run.
    def slow(i):
        def dec(b):
            time.sleep(0.004)
            return b + bytes([i % 256])
        return dec
    g = Graph(tuple(Codec(f"slow{i}", C.STRICT, slow(i)) for i in range(300)), xor=False)
    t = time.monotonic()
    r = g.search(b"seed", ORACLE, deadline=t + 0.1)
    assert r.truncated == "deadline" and time.monotonic() - t < 0.8


def test_bare_ascii85_with_spaces_is_prose_not_ascii85():
    assert by_name("a85").decode(b"87cURDZ") == b"Hello"
    assert by_name("a85").decode(b"87cU RDZ") is None
    assert by_name("a85").decode(b"<~87cU RDZ~>") == b"Hello"


def _toy(name, kind, mapping):
    return Codec(name, kind, lambda b, m=mapping: m.get(b))


def test_two_loose_steps_in_a_row_are_never_taken():
    # l1 then l2 would reach the flag, but two keyless steps back to back prove nothing about each other.
    s = _toy("s", C.STRICT, {b"mid": b"some text"})          # makes l1's output read on (passes the gate)
    l1 = _toy("l1", C.LOOSE, {b"seed": b"mid"})
    l2 = _toy("l2", C.LOOSE, {b"mid": b"CSCTF{two_loose}"})
    assert Graph((s, l1, l2), xor=False).search(b"seed", ORACLE).hits == []
    s2 = _toy("s2", C.STRICT, {b"mid": b"between"})
    l3 = _toy("l3", C.LOOSE, {b"between": b"CSCTF{loose_strict_loose}"})
    r = Graph((s2, l1, l3), xor=False).search(b"seed", ORACLE)
    assert r.unique == "CSCTF{loose_strict_loose}" and r.hits[0].chain == ("l1", "s2", "l3")


def test_all_depths_keeps_deeper_answers_and_the_default_stops_at_the_first_goal_depth():
    a = _toy("a", C.STRICT, {b"seed": b"CSCTF{shallow}"})
    b = _toy("b", C.STRICT, {b"seed": b"mid"})
    c = _toy("c", C.STRICT, {b"mid": b"CSCTF{deep}"})
    g = Graph((a, b, c), xor=False)
    assert g.search(b"seed", ORACLE).answers == ["CSCTF{shallow}"]
    assert g.search(b"seed", ORACLE, all_depths=True).answers == ["CSCTF{shallow}", "CSCTF{deep}"]


def test_a_state_reached_twice_is_one_hit():
    s1 = _toy("s1", C.STRICT, {b"seed": b"x1"})
    s2 = _toy("s2", C.STRICT, {b"seed": b"x2"})
    t1 = _toy("t1", C.STRICT, {b"x1": b"CSCTF{same}"})
    t2 = _toy("t2", C.STRICT, {b"x2": b"CSCTF{same}"})
    r = Graph((s1, s2, t1, t2), xor=False).search(b"seed", ORACLE)
    assert len(r.hits) == 1 and r.hits[0].chain == ("s1", "t1")


def test_a_loose_step_reads_on_into_binary_that_a_printable_xor_key_opens():
    # caesar3 + b64 + xor0x55 + b64: after the caesar step, base64 gives xor'd bytes that are not text; the
    # gate follows it because a key exists that makes every byte printable.
    xored = xor(base64.b64encode(P), 0x55)
    assert not C.is_text(xored), "precondition: the middle layer is binary"
    data = caesar(base64.b64encode(xored), 3)
    r = Graph().search(data, ORACLE)
    assert r.unique == FLAG and r.hits[0].chain == ("caesar3", "b64", "xor0x55", "b64")


def test_anyof_is_strong_only_for_a_state_its_strong_member_accepts():
    data = caesar(b"some prose then " + FLAG.encode() + b" and more", 13)
    r = Graph().search(data, AnyOf(CribOracle("absent crib text"), ORACLE))
    assert r.unique == FLAG and not r.hits[0].confirmed, "only the flag shape matched: a loose chain stays unconfirmed"
    r = Graph().search(data, AnyOf(CribOracle("some prose"), ORACLE))
    assert r.hits[0].confirmed


def test_decompression_stops_exactly_at_max_out():
    assert C.d_zlib(zlib.compress(b"\x00" * C.MAX_OUT)) == b"\x00" * C.MAX_OUT
    assert C.d_zlib(zlib.compress(b"\x00" * (C.MAX_OUT + 1))) is None


# --------------------------------------------------------------------------- contract bounds (fix round 1)

def test_max_loose_caps_the_loose_steps_of_one_chain():
    # Four loose steps, never two in a row: rot47, b64, rot13, b64, reverse, b64, atbash. MAX_LOOSE=3 refuses
    # the chain; max_loose=4 finds it. A walk that did not count loose steps would find it at 3.
    chain = ("rot47", "b64", "rot13", "b64", "reverse", "b64", "atbash")
    data = enc(chain, P)
    assert Graph().max_loose == 3
    capped = Graph(max_loose=3).search(data, ORACLE)
    assert capped.hits == [] and capped.truncated is None, "the cap, not a bound, stopped it"
    r = Graph(max_loose=4).search(data, ORACLE)
    assert r.unique == FLAG and r.hits[0].chain == chain
    three = enc(chain[1:], P)                                   # drop the outer rot47: three loose steps
    assert Graph(max_loose=3).search(three, ORACLE).hits[0].chain == chain[1:]


def test_pack_codecs_are_asked_only_on_states_up_to_pack_max_state():
    from ctf.codec import graph as G
    asked = []

    def spy(b):
        asked.append(len(b))
        return None
    g = Graph((Codec("p.spy", C.PACK, spy),), xor=False, max_loose=0)
    limit = G.PACK_MAX_STATE
    assert limit == 8 << 10
    g.search(b"A" * limit, ORACLE)
    assert asked == [limit], "a state of exactly PACK_MAX_STATE bytes is asked"
    asked.clear()
    g.search(b"A" * (limit + 1), ORACLE)
    assert asked == [], "a state over PACK_MAX_STATE is never handed to a pack codec"
    strict = []
    Graph((Codec("s.spy", C.STRICT, lambda b: strict.append(len(b))),), xor=False, max_loose=0).search(
        b"A" * (limit + 1), ORACLE)
    assert strict == [limit + 1], "the bound is for pack codecs only"


def test_a_codec_that_raises_still_spends_the_node_budget():
    calls = []

    def boom(b):
        calls.append(b)
        raise RuntimeError("refused")
    r = Graph((Codec("boom", C.STRICT, boom),), xor=False, max_loose=0, max_nodes=1).search(b"abc", ORACLE)
    assert r.nodes == 1 and r.truncated == "nodes" and len(calls) == 1
    ok = Graph((Codec("boom", C.STRICT, boom),), xor=False, max_loose=0, max_nodes=2).search(b"abc", ORACLE)
    assert ok.nodes == 1 and ok.truncated is None
