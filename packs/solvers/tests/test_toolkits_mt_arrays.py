"""B-063: the MT19937 word-array detector engine (solvers/toolkits/mt_arrays.py) and the `mt-rewind`
operation of the prng_recovery CLI.

Every fixture is built here. The streams come from CPython's own generator (`random.Random`), so the
expected earlier and later outputs are the real ones, not values the engine computed. CBOR and
MessagePack bytes are written by the small encoders below, not by the decoder the engine uses.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

import pytest

import mt_arrays as ma
import prng_recovery
from _shadowed import common_module
from ctf import event
from ctf.result import SolverResult

mc = common_module("modern_crypto")
REPO = Path(__file__).resolve().parents[1]
SEED = 20261107


def _profile():
    return event.parse({
        "slug": "b063-test", "name": "mt arrays test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()


def _stream(seed, generations):
    r = random.Random(seed)
    outputs, words = [], []
    for _ in range(generations):
        outputs += [r.getrandbits(32) for _ in range(624)]
        words += list(r.getstate()[1][:624])           # the raw state words behind those outputs
    return outputs, words


OUT, X = _stream(SEED, 6)
W = OUT[100:900]                                        # 800 outputs, 100 outputs after the seeding
JUNK = [int.from_bytes(hashlib.sha256(b"not mt %d" % i).digest()[:4], "big") for i in range(900)]


def cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << 8 * size:
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if v is None:
        return b"\xf6"
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


def msgpack_words(key: str, words) -> bytes:
    """{key: [uint32, ...]} as MessagePack: fixmap, fixstr, array 16, uint 32 items."""
    return (b"\x81" + bytes([0xA0 | len(key)]) + key.encode() + b"\xdc" + len(words).to_bytes(2, "big")
            + b"".join(b"\xce" + w.to_bytes(4, "big") for w in words))


def one(files, **kw):
    rep = ma.examine(files, **kw)
    assert len(rep.findings) == 1, [f.line() for f in rep.findings]
    return rep.findings[0]


# ---- every reading of a file as words --------------------------------------------------------------

LE = struct.pack("<800I", *W)
BE = struct.pack(">800I", *W)

READINGS = [
    ("list.json", json.dumps(W).encode(), "$", "integers", 0),
    ("nested.json", json.dumps({"a": {"b c": W, "n": 5}}).encode(), '$.a["b c"]', "integers", 0),
    ("header.json", json.dumps({"log": [7, 8, 9] + W + [1, 2]}).encode(), "$.log", "integers", 3),
    ("rows.json", json.dumps({"tx": [{"id": i, "words": W[i * 8:i * 8 + 8]} for i in range(100)]}).encode(),
     "$.tx[*].words", "one field of each record, rows joined", 0),
    ("column.json", json.dumps([{"n": i, "out": w} for i, w in enumerate(W)]).encode(),
     "$[*].out", "one field of each record", 0),
    ("grid.json", json.dumps([W[i:i + 16] for i in range(0, 800, 16)]).encode(), "$", "integers, rows joined", 0),
    ("decimal-strings.json", json.dumps([str(w) for w in W]).encode(), "$", "integers", 0),
    ("hex-strings.json", json.dumps([f"0x{w:08x}" for w in W]).encode(), "$", "integers", 0),
    ("bare-hex-strings.json", json.dumps([f"{w:08X}" for w in W]).encode(), "$", "integers", 0),
    ("signed.json", json.dumps([w - (1 << 32) if w >> 31 else w for w in W]).encode(),
     "$", "integers as two's-complement int32", 0),
    ("wide-low.json", json.dumps([W[i] | W[i + 1] << 32 for i in range(0, 800, 2)]).encode(),
     "$", "integers each split into 2 32-bit words, low word first", 0),
    ("wide-high.json", json.dumps([W[i] << 32 | W[i + 1] for i in range(0, 800, 2)]).encode(),
     "$", "integers each split into 2 32-bit words, high word first", 0),
    ("hex.json", json.dumps({"dump": BE.hex()}).encode(), "$.dump", "hex string as big-endian uint32", 0),
    ("hex-in-list.json", json.dumps(["v1", LE.hex()]).encode(), "$[1]", "hex string as little-endian uint32", 0),
    ("b64.json", json.dumps({"dump": base64.b64encode(LE).decode()}).encode(),
     "$.dump", "base64 string as little-endian uint32", 0),
    ("lines.jsonl", "\n".join(json.dumps({"out": w}) for w in W).encode(), "$[*].out", "one field of each record", 0),
    ("journal.cbor", cbor({"unit": "KW-7", "registers": {"words": W}, "ok": True, "none": None}),
     "$.registers.words", "integers", 0),
    ("bytes-le.cbor", cbor({"blob": LE}), "$.blob", "byte string as little-endian uint32", 0),
    ("bytes-be.cbor", cbor([1, {"blob": BE}]), "$[1].blob", "byte string as big-endian uint32", 0),
    ("chunks.cbor", cbor({"parts": [LE[i:i + 400] for i in range(0, 3200, 400)]}),
     "$.parts", "integers, byte strings joined, as little-endian uint32", 0),
    ("words.msgpack", msgpack_words("w", W), "$.w", "integers", 0),
    ("out.txt", "\n".join(str(w) for w in W).encode(), "$", "integers in the text, in order", 0),
    ("python.txt", ("outputs = " + repr(W) + "\n").encode(), "$", "integers in the text, in order", 0),
    ("hexnum.txt", " ".join(hex(w) for w in W).encode(), "$", "integers in the text, in order", 0),
    ("indexed.txt", "\n".join(f"out[{i}] = {w}" for i, w in enumerate(W)).encode(),
     "$", "the last integer on each line", 0),
    ("hexwords.txt", "\n".join(f"{w:08x}" for w in W).encode(), "$", "8-digit hex words", 0),
    ("dump-le.bin", LE + b"\x01\x02", "$", "whole file as little-endian uint32", 0),
    ("dump-be.bin", struct.pack(">3I", 1, 2, 3) + BE, "$", "whole file as big-endian uint32", 3),
]


@pytest.mark.parametrize("name, data, path, reading, start", READINGS, ids=[r[0] for r in READINGS])
def test_a_stream_is_found_in_every_form_it_is_written_in(name, data, path, reading, start):
    f = one({name: data})
    assert (f.file, f.path, f.reading, f.mode) == (name, path, reading, "outputs")
    assert (f.start, f.length, f.verified) == (start, 800, 176)
    assert f.next == OUT[900:900 + 624]
    assert f.previous == OUT[:100]                      # the 100 outputs drawn before it, and no more
    assert f.seed == {"outputs_before": 100, "kind": "init_by_array", "key": [SEED], "python_seed": SEED}


def test_integers_of_three_words_each():
    data = json.dumps([W[i] | W[i + 1] << 32 | W[i + 2] << 64 for i in range(0, 798, 3)]).encode()
    f = one({"wide3.json": data})
    assert f.reading == "integers each split into 3 32-bit words, low word first"
    assert (f.start, f.length, f.verified) == (0, 798, 174) and f.next[:2] == OUT[898:900]


def test_records_that_do_not_all_have_a_field_and_deep_nesting():
    records = [{"n": i, "out": w} for i, w in enumerate(W)]
    records[0]["extra"] = 1                                   # only the first record has it
    records[5]["late"] = 2
    f = one({"a.json": json.dumps(records).encode()})
    assert (f.path, f.reading, f.length) == ("$[*].out", "one field of each record", 800)
    deep = W
    for _ in range(60):                                       # deeper than any decoder bound in the repo
        deep = [deep]
    f = one({"deep.json": json.dumps({"k": deep}).encode()})
    inner = "$.k" + "[0]" * 60
    assert (f.path, f.reading, f.length) == (inner[:-3], "integers, rows joined", 800)   # its one row, joined
    assert f.also_at == [f"deep.json {inner} (integers)"]
    strings = ["x", "0x10", W, "y"]                           # short strings beside the list do not hide it
    assert one({"s.json": json.dumps(strings).encode()}).path == "$[2]"


def test_the_format_each_file_was_read_as():
    got = {name: ma.read_document(data)[0] for name, data, *_ in READINGS}
    assert {got["list.json"], got["lines.jsonl"], got["journal.cbor"], got["words.msgpack"], got["out.txt"],
            got["dump-le.bin"]} == {"json", "jsonl", "cbor", "msgpack", "text", "raw"}
    assert ma.read_document(b"[1, 2,")[0] == "text"            # broken JSON is still text with integers
    assert ma.read_document(b'{"a": 1}\nnot json\n')[0] == "text"
    assert ma.read_document(b"\x00\x01")[0] == "raw"


def test_a_dumped_state_table_is_found_as_state_words():
    f = one({"table.json": json.dumps({"mt": X[700:1500]}).encode()})
    assert (f.mode, f.path, f.start, f.length, f.verified) == ("state", "$.mt", 0, 800, 176)
    assert f.next == X[1500:1500 + 624]
    assert f.previous == X[76:700]                      # raw state words, one generation back
    assert f.seed["outputs_before"] == 700
    assert "raw state words" in f.line() and "outputs" not in f.line().split(":")[0]


def test_the_reported_state_continues_the_stream_in_cpython():
    f = one({"list.json": json.dumps(W).encode()})
    clone = random.Random()
    clone.setstate((3, tuple(f.state) + (624,), None))
    assert [clone.getrandbits(32) for _ in range(1000)] == OUT[900:1900]
    assert f.to_dict()["state"] == {"words": X[276:900], "index": 624,
                                    "note": "raw state words after the stretch's last word; index 624 = twist next"}


def test_rewind_and_forward_counts_and_the_indexes_in_the_report():
    data = json.dumps({"log": JUNK[:5] + OUT[2000:2700]}).encode()
    f = one({"a.json": data}, rewind=1300, forward=3, seed_search=0)
    assert f.seed is None
    assert f.previous == OUT[700:2000] and f.next == OUT[2700:2703]
    d = f.to_dict()
    assert d["previous"] == {"first_index": 5 - 1300, "values": OUT[700:2000]}
    assert d["next"] == {"first_index": 705, "values": OUT[2700:2703]}
    assert (d["start"], d["length"], d["verified"], d["proven"]) == (5, 700, 76, True)
    f = one({"a.json": data}, rewind=0, forward=0)
    assert f.previous == [] and f.next == []


def test_previous_outputs_stop_at_the_seeding_when_it_is_in_reach():
    # captured from the first output on: nothing came before
    f = one({"a.json": json.dumps(OUT[:700]).encode()})
    assert f.previous == [] and f.seed["outputs_before"] == 0
    assert "random.seed(20261107), 0 outputs before this stretch" in f.line()
    # 100 outputs in: asking for 100, 101 or 99 back gives at most the 100 real ones
    assert one({"a.json": json.dumps(W).encode()}, rewind=100).previous == OUT[:100]
    assert one({"a.json": json.dumps(W).encode()}, rewind=101).previous == OUT[:100]
    assert one({"a.json": json.dumps(W).encode()}, rewind=99).previous == OUT[1:100]
    # 2000 outputs in, asked for 3000 back: only the 2000 real ones
    f = one({"a.json": json.dumps(OUT[2000:2700]).encode()}, rewind=3000)
    assert f.previous == OUT[:2000] and f.seed["outputs_before"] == 2000
    # the seeding is out of the search's reach: the rewind is arithmetic and says nothing of a seed
    f = one({"a.json": json.dumps(OUT[2000:2700]).encode()}, rewind=3000, seed_search=1999)
    assert f.seed is None and len(f.previous) == 3000 and f.previous[1000:] == OUT[:2000]
    assert "seeded" not in f.line()


def test_a_text_seed_is_named_in_the_line():
    r = random.Random("standing order")
    data = json.dumps([r.getrandbits(32) for _ in range(700)]).encode()
    f = one({"a.json": data})
    assert f.seed["python_seed_bytes"] == b"standing order".hex()
    assert f"random.seed(bytes.fromhex('{b'standing order'.hex()}'))" in f.line()


def test_seed_lines():
    assert ma.seed_line({"outputs_before": 1, "kind": "init_genrand", "seed": 5489}) == (
        "stream seeded by init_genrand(5489), 1 output before this stretch")
    assert ma.seed_line({"outputs_before": 0, "kind": "init_by_array", "key": [7], "python_seed": 7}) == (
        "stream seeded by random.seed(7), 0 outputs before this stretch")
    big = (1 << 256) + 1
    key = [big >> 32 * i & 0xFFFFFFFF for i in range(9)]
    assert ma.seed_line({"outputs_before": 2, "kind": "init_by_array", "key": key, "python_seed": big}) == (
        "stream seeded by init_by_array, a 9-word key, 2 outputs before this stretch")
    assert "random.seed(" in ma.seed_line(
        {"outputs_before": 2, "kind": "init_by_array", "key": key[:8], "python_seed": (1 << 256) - 1})


def test_a_bare_window_is_reported_unverified_everywhere():
    rep = ma.examine({"a.json": json.dumps(OUT[1000:1624]).encode()})
    f = rep.findings[0]
    assert (f.verified, f.proven, f.to_dict()["proven"]) == (0, False, False)
    assert "UNVERIFIED" in f.line() and "do not answer" in f.line()
    res = ma.result_of(rep)
    assert res.status == "unsure" and not res.flags
    assert [e.kind for e in res.evidence] == ["unverified"]
    assert "(0 proven, 1 unverified)" in res.notes


def test_how_much_was_verified_is_said_in_the_line():
    assert "76 verified by the recurrence (under 624" in one({"a": json.dumps(OUT[:700]).encode()}).line()
    line = one({"a": json.dumps(OUT[:1248]).encode()}).line()
    assert "624 verified by the recurrence (every given word checked)" in line


def test_proven_stretches_come_first_and_two_streams_are_two_findings():
    second = random.Random(7)
    other = [second.getrandbits(32) for _ in range(900)]
    rep = ma.examine({"a.json": json.dumps({"bare": OUT[3000:3624], "one": W, "two": other}).encode()})
    assert [(f.path, f.verified) for f in rep.findings] == [("$.one", 176), ("$.two", 276), ("$.bare", 0)]
    assert rep.findings[1].seed["python_seed"] == 7
    rep = ma.examine({"a.json": json.dumps([W, other, "end"]).encode(),
                      "b.txt": " ".join(str(v) for v in OUT[3000:3700]).encode()})
    assert [(f.file, f.path) for f in rep.findings] == [("a.json", "$[0]"), ("a.json", "$[1]"), ("b.txt", "$")]


def test_the_same_words_under_two_readings_are_one_finding():
    rows = [W[i:i + 400] for i in range(0, 800, 400)] + [W]          # the third row is the first two, joined
    rep = ma.examine({"a.json": json.dumps({"rows": rows[:2], "all": rows[2]}).encode()})
    assert len(rep.findings) == 1
    f = rep.findings[0]
    assert f.path == "$.rows" and f.also_at == ["a.json $.all (integers)"]
    assert f.to_dict()["also_at"] == ["a.json $.all (integers)"]


def test_outputs_and_the_state_words_behind_them_are_two_findings():
    # one span of the generator logged twice: as outputs and as the raw table. Both recover the same
    # state, but they are different lists in different forms, and each keeps its own next and previous.
    rep = ma.examine({"a.json": json.dumps({"out": OUT[1000:1700], "mt": X[1000:1700]}).encode()},
                     rewind=2, forward=2, seed_search=0)
    assert [(f.path, f.mode) for f in rep.findings] == [("$.out", "outputs"), ("$.mt", "state")]
    assert rep.findings[0].state == rep.findings[1].state == X[1076:1700]
    assert rep.findings[0].next == OUT[1700:1702] and rep.findings[1].next == X[1700:1702]
    assert rep.findings[0].also_at == rep.findings[1].also_at == []


def test_files_without_a_stream_give_nothing():
    files = {
        "junk.json": json.dumps(JUNK).encode(),
        "small.json": json.dumps(list(range(5000))).encode(),
        "short.json": json.dumps(OUT[:623]).encode(),
        "mixed.json": json.dumps(W[:400] + ["x"] + W[400:]).encode(),
        "mixed-rows.json": json.dumps([W[:400], ["x"], W[400:]]).encode(),
        "floats.json": json.dumps([float(w) for w in W]).encode(),
        "bools.json": json.dumps([True] * 700).encode(),
        "negative-wide.json": json.dumps([-(1 << 40)] + W).encode(),
        "prose.txt": b"nothing to see here\n" * 50,
        "short.bin": LE[:2492],
        "empty.json": b"[]",
        "nothing": b"",
    }
    rep = ma.examine(files)
    assert rep.findings == [] and rep.complete and rep.files == len(files)
    res = ma.result_of(rep)
    assert res.status == "none" and res.evidence == ()
    assert res.notes.startswith(f"no MT19937 stretch in {rep.lists} word lists of {len(files)} files")
    assert rep.lists == 2                                # junk and small: the two that read as >= 624 words


def test_word_readings_bounds():
    assert ma.word_readings([]) == []
    assert ma.word_readings(W[:623]) == []
    assert ma.word_readings([0xFFFFFFFF] * 624) == [("", [0xFFFFFFFF] * 624)]         # the largest word is a word
    assert ma.word_readings([-(1 << 31)] + [(1 << 31) - 1] * 623) == [
        ("as two's-complement int32", [1 << 31] + [(1 << 31) - 1] * 623)]
    assert ma.word_readings([-1] + [1 << 31] * 623) == []                            # neither signed nor unsigned
    assert ma.word_readings([w - (1 << 32) if w >> 31 else w for w in W[:623]]) == []
    wide = [W[i] | W[i + 1] << 32 for i in range(0, 622, 2)]                  # 311 pairs: 622 words
    assert ma.word_readings(wide) == []
    assert [how for how, _ in ma.word_readings(wide + [1 << 63])] == [
        "each split into 2 32-bit words, low word first", "each split into 2 32-bit words, high word first"]
    assert ma.word_readings([1 << 32 * 624]) == []                           # 625 words wide: over MAX_SPLIT
    low, high = ma.word_readings([(1 << 32 * 624) - 1])
    assert low[1] == high[1] == [0xFFFFFFFF] * 624
    assert ma.numbers([1, True]) is None and ma.numbers(["1", 2]) is None and ma.numbers([]) is None
    assert ma.numbers(["10", "0x10"]) == [16, 16] and ma.numbers(["10", "11"]) == [10, 11]
    assert ma.numbers(["-5", "7"]) == [-5, 7] and ma.numbers(["zz"]) is None
    assert ma.byte_readings(LE[:2495]) == []
    assert [len(words) for _, words in ma.byte_readings(LE[:2499])] == [624, 624]


def test_a_list_over_the_scan_bound_is_cut_and_named(monkeypatch):
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 700)
    rep = ma.examine({"a.json": json.dumps(W).encode()})
    assert [(f.start, f.length) for f in rep.findings] == [(0, 700)]
    assert rep.notes == ["a.json: $ (integers): only the first 700 of 800 words were tested"]
    assert (rep.complete, rep.partial, rep.to_dict()["partial"]) == (True, True, True)
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 800)         # exactly at the bound: all of it, no note
    rep = ma.examine({"a.json": json.dumps(W).encode()})
    assert [(f.start, f.length) for f in rep.findings] == [(0, 800)] and rep.notes == []
    assert (rep.partial, rep.to_dict()["partial"]) == (False, False)


def test_nothing_found_in_a_list_tested_in_part_is_not_none(monkeypatch):
    # the stream sits past the cut: what was tested holds nothing, which is not "ran to the end, found nothing"
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 800)
    rep = ma.examine({"a.json": json.dumps(JUNK[:800] + W).encode()})
    res = ma.result_of(rep)
    assert rep.findings == [] and rep.complete and rep.partial
    assert res.status == "unsure" and "(not every list was tested in full)" in res.notes
    assert "a.json: $ (integers): only the first 800 of 1600 words were tested" in res.notes
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 1600)        # the whole list tested: the stream is found
    assert [f.start for f in ma.examine({"a.json": json.dumps(JUNK[:800] + W).encode()}).findings] == [800]
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 1 << 20)
    assert ma.result_of(ma.examine({"a.json": json.dumps(JUNK).encode()})).status == "none"


def test_a_cbor_file_over_the_decoder_bound_is_named_not_dropped(monkeypatch):
    import wire_decode
    data = cbor({"words": W})
    assert ma.read_document(data)[0] == "cbor"
    monkeypatch.setattr(wire_decode, "MAX_ITEMS", 100)
    fmt, _, note = ma.read_document(data)
    assert fmt == "raw" and "cbor decode stopped at the decoder's bound (too many items)" in note
    rep = ma.examine({"j.cbor": data})
    assert rep.findings == [] and rep.notes == [f"j.cbor: {note}"]
    assert "j.cbor: cbor decode stopped" in ma.result_of(rep).notes
    assert ma.read_document(b"\x00\x01\xff")[2] is None        # not CBOR at all: nothing to say


# ---- budget and options ----------------------------------------------------------------------------

def test_the_budget_stops_before_a_list_and_names_what_was_not_tested():
    ticks = iter(range(100))
    files = {"a.json": json.dumps({"first": W, "second": OUT[2000:2700]}).encode(),
             "b.json": json.dumps(OUT[3000:3700]).encode()}
    # start 0; a.json is opened at 1, its lists are met at 2 and 3
    rep = ma.examine(files, seconds=2.5, clock=lambda: next(ticks))
    assert [f.path for f in rep.findings] == ["$.first"]
    assert (rep.complete, rep.lists, rep.files) == (False, 1, 1)
    assert rep.notes == ["a.json: stopped at $.second (integers): the budget of 2.5 s was spent",
                         "b.json: not read, the budget of 2.5 s was spent"]
    assert ma.result_of(rep).status == "unsure"
    # exactly at the budget is spent: the list met at tick 3 with a budget of 3 is not tested
    ticks = iter(range(100))
    rep = ma.examine(files, seconds=3, clock=lambda: next(ticks))
    assert [f.path for f in rep.findings] == ["$.first"] and (rep.complete, rep.lists) == (False, 1)
    assert rep.notes[0] == "a.json: stopped at $.second (integers): the budget of 3 s was spent"
    # nothing found and not finished is not "none"
    ticks = iter(range(100))
    rep = ma.examine({"a.json": json.dumps({"first": JUNK, "second": W}).encode()}, seconds=2.5,
                     clock=lambda: next(ticks))
    res = ma.result_of(rep)
    assert rep.findings == [] and res.status == "unsure" and "not every list was tested" in res.notes
    # with budget left the same file is read to the end
    ticks = iter(range(100))
    rep = ma.examine({"a.json": json.dumps({"first": JUNK, "second": W}).encode()}, seconds=50,
                     clock=lambda: next(ticks))
    assert rep.complete and [f.path for f in rep.findings] == ["$.second"]


def test_files_are_read_one_at_a_time_and_not_once_the_budget_is_spent(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("no numbers here")                  # no list: nothing checks the clock in it
    (tmp_path / "b.json").write_text(json.dumps(W))
    (tmp_path / "c.json").write_text(json.dumps(OUT[3000:3700]))
    read = []
    real = ma.read_file

    def spy(path):
        read.append(path.name)
        return real(path)

    monkeypatch.setattr(ma, "read_file", spy)
    files = {n: tmp_path / n for n in ("a.txt", "b.json", "c.json")}
    ticks = iter(range(100))                                             # start 0; a.txt opened at 1, b.json at 2
    rep = ma.examine(files, seconds=2, clock=lambda: next(ticks))
    assert read == ["a.txt"] and rep.files == 1 and not rep.complete
    assert rep.notes == ["b.json: not read, the budget of 2 s was spent", "c.json: not read, the budget of 2 s was spent"]
    # with budget, each file is read when its turn comes, after the one before it was examined
    read.clear()
    seen_reads = []
    real_findings = ma.findings_in

    def findings(view, **kw):
        seen_reads.append(list(read))
        return real_findings(view, **kw)

    monkeypatch.setattr(ma, "findings_in", findings)
    rep = ma.examine(files)
    assert read == ["a.txt", "b.json", "c.json"] and [f.file for f in rep.findings] == ["b.json", "c.json"]
    assert seen_reads == [["a.txt", "b.json"], ["a.txt", "b.json", "c.json"]]    # c.json not read while b.json is tested


def test_a_file_that_cannot_be_read_when_its_turn_comes_is_named(tmp_path, monkeypatch):
    (tmp_path / "a.json").write_text(json.dumps(W))
    files = {"gone.json": tmp_path / "gone.json", "a.json": tmp_path / "a.json"}
    rep = ma.examine(files)
    assert [f.file for f in rep.findings] == ["a.json"] and rep.files == 1
    assert rep.notes == ["gone.json: not read (No such file or directory)"]
    monkeypatch.setattr(ma, "MAX_FILE", 100)                             # grew past the bound after listing
    rep = ma.examine({"a.json": tmp_path / "a.json"})
    assert rep.findings == [] and rep.notes == ["a.json: not read (over 0 MiB)"]
    monkeypatch.setattr(ma, "MAX_FILE", len(json.dumps(W)))               # exactly at the bound: read
    assert len(ma.examine({"a.json": tmp_path / "a.json"}).findings) == 1


@pytest.mark.parametrize("kw", [
    {"rewind": -1}, {"rewind": 65537}, {"rewind": "5"}, {"rewind": True}, {"forward": -1}, {"forward": 65537},
    {"seed_search": -1}, {"seed_search": 65536 - 623}, {"seconds": 0}, {"seconds": -1}, {"seconds": "9"},
    {"seconds": True},
])
def test_options_outside_their_bounds_are_refused(kw, tmp_path):
    with pytest.raises(ma.OptionError) as err:
        ma.examine({"a.json": json.dumps(W).encode()}, **kw)
    assert next(iter(kw)) in str(err.value)
    (tmp_path / "a.json").write_text(json.dumps(W))
    res = ma.solve(tmp_path, PROFILE, **kw)
    assert res.status == "blocked" and next(iter(kw)) in res.notes
    assert not (tmp_path / "recon").exists()


def test_the_largest_counts_are_accepted():
    f = one({"a.json": json.dumps(OUT[2000:2700]).encode()}, rewind=65536, forward=65536, seed_search=65536 - 624)
    assert len(f.next) == 65536 and f.next[:1000] == OUT[2700:3700]
    assert f.previous == OUT[:2000]


def test_solve_refuses_an_unknown_option_and_a_missing_folder(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(W))
    res = ma.solve(tmp_path, PROFILE, rewnd=5)
    assert res.status == "blocked" and "unknown option rewnd" in res.notes
    res = ma.solve(tmp_path / "nope", PROFILE)
    assert res.status == "blocked" and "no such challenge folder" in res.notes


# ---- the engine contract ---------------------------------------------------------------------------

def test_challenge_files_prefer_the_sweep_copy_and_skip_recon(tmp_path, monkeypatch):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.json").write_bytes(b"[1]")
    (tmp_path / "notes.md").write_text("x")
    assert set(ma.challenge_files(tmp_path)) == {"files/a.json"}
    (tmp_path / "unpacked" / "z.zip.unpacked").mkdir(parents=True)
    (tmp_path / "unpacked" / "a.json").write_bytes(b"[1]")
    (tmp_path / "unpacked" / "z.zip.unpacked" / "m.cbor").write_bytes(b"\x80")
    (tmp_path / "unpacked" / ".sweep.json").write_text("{}")
    (tmp_path / "unpacked" / "recon").mkdir()
    (tmp_path / "unpacked" / "recon" / "old.json").write_bytes(b"[2]")
    (tmp_path / "unpacked" / "link.json").symlink_to(tmp_path / "files" / "a.json")
    assert ma.challenge_files(tmp_path) == {"unpacked/a.json": tmp_path / "unpacked" / "a.json",
                                            "unpacked/z.zip.unpacked/m.cbor": tmp_path / "unpacked/z.zip.unpacked/m.cbor"}
    with pytest.raises(FileNotFoundError):
        ma.challenge_files(tmp_path / "nope")
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "x.txt").write_text("1")
    (bare / "challenge.json").write_text("{}")
    assert set(ma.challenge_files(bare)) == {"x.txt"}
    # bounds are named, never silent
    monkeypatch.setattr(ma, "MAX_FILE", 2)
    notes = []
    assert set(ma.challenge_files(tmp_path, notes)) == {"unpacked/z.zip.unpacked/m.cbor"}
    assert notes == ["unpacked/a.json: not read, over 0 MiB"]
    monkeypatch.setattr(ma, "MAX_FILE", 8 << 20)
    monkeypatch.setattr(ma, "MAX_FILES", 1)
    notes = []
    assert set(ma.challenge_files(tmp_path, notes)) == {"unpacked/a.json"}
    assert notes == ["unpacked/z.zip.unpacked/m.cbor: not read, past the first 1 files"]


def test_challenge_files_list_without_reading_and_put_structured_files_first(tmp_path, monkeypatch):
    up = tmp_path / "unpacked"
    (up / "node_modules" / "x").mkdir(parents=True)
    for name in ("a.png", "node_modules/x/index.js", "zz/package.json", "b.BIN", "out.TXT", "k.cbor", "m.msgpack",
                 "r.jsonl"):
        (up / name).parent.mkdir(parents=True, exist_ok=True)
        (up / name).write_bytes(b"[1]")
    # listing reads no file: a web handout's bundles are not loaded into memory to be listed
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail(f"read {self}"))
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: pytest.fail(f"opened {self}"))
    got = ma.challenge_files(tmp_path)
    assert list(got) == ["unpacked/k.cbor", "unpacked/m.msgpack", "unpacked/out.TXT", "unpacked/r.jsonl",
                         "unpacked/zz/package.json", "unpacked/a.png", "unpacked/b.BIN",
                         "unpacked/node_modules/x/index.js"]
    assert all(isinstance(v, Path) and v == tmp_path / k for k, v in got.items())
    # the file cap keeps the structured files and names the others
    monkeypatch.setattr(ma, "MAX_FILES", 5)
    notes = []
    assert list(ma.challenge_files(tmp_path, notes))[-1] == "unpacked/zz/package.json"
    assert notes == [f"unpacked/{n}: not read, past the first 5 files"
                     for n in ("a.png", "b.BIN", "node_modules/x/index.js")]


def test_solve_names_a_file_it_did_not_read(tmp_path, monkeypatch):
    (tmp_path / "big.json").write_text(json.dumps(W))
    monkeypatch.setattr(ma, "MAX_FILE", 100)
    res = ma.solve(tmp_path, PROFILE)
    assert res.status == "none" and "big.json: not read, over 0 MiB" in res.notes


def _key_wheel(tmp_path):
    """A synthetic journal in the shape of the challenge this item closes (CSCTF 9094): the generator
    drew 8 words per transmission key; the journal records 1248 register words from a later window and
    the sealed dispatches, and the standing order (tx 155) was sealed before that window."""
    r = random.Random(0x9094)
    drawn = [r.getrandbits(32) for _ in range(156 * 8)]            # tx 0..155, all before the window
    window = [r.getrandbits(32) for _ in range(1248)]
    later = [r.getrandbits(32) for _ in range(700)]
    order = b"CSCTF{synthetic_standing_order_b063}"

    def seal(tx, text):
        key = b"".join(w.to_bytes(4, "big") for w in drawn[tx * 8:tx * 8 + 8])
        stream = b"".join(hashlib.sha256(key + n.to_bytes(4, "big")).digest() for n in range(2))
        return bytes(a ^ b for a, b in zip(text, stream))

    journal = {"unit": "KW-7", "schedule": {"words_per_tx": 8, "keystream": "SHA-256(key || counter)"},
               "register_window": {"first_tx": 156, "words": window},
               "dispatches": [{"tx": 155, "kind": "standing order", "sealed": seal(155, order)},
                              {"tx": 154, "kind": "resupply", "sealed": seal(154, b"fuel at grid 7, 0400")}]}
    cd = tmp_path / "9094-the-key-wheel"
    (cd / "files").mkdir(parents=True)
    (cd / "files" / "key-unit-journal.cbor").write_bytes(cbor(journal))
    return cd, drawn, window, later, order, journal


def test_a_key_wheel_journal_is_reopened_from_the_engine_report(tmp_path):
    cd, drawn, window, later, order, journal = _key_wheel(tmp_path)
    res = ma.solve(cd, PROFILE)
    assert isinstance(res, SolverResult) and res.status == "unsure" and res.flags == ()
    assert res.engine == "toolkits.mt_arrays"
    assert [e.kind for e in res.evidence] == ["match"]
    assert res.evidence[0].path == "files/key-unit-journal.cbor"
    assert "1248 consecutive 32-bit words at $.register_window.words" in res.evidence[0].detail
    assert "624 verified by the recurrence (every given word checked)" in res.evidence[0].detail
    assert "recon/mt_arrays/mt_arrays.json" in res.notes and "the flag is not" in res.notes

    rep = json.loads((cd / "recon" / "mt_arrays" / "mt_arrays.json").read_text())
    assert (rep["schema"], rep["engine"], rep["complete"]) == (1, "toolkits.mt_arrays", True)
    f, = rep["findings"]
    assert (f["mode"], f["start"], f["length"], f["verified"], f["proven"]) == ("outputs", 0, 1248, 624, True)
    assert f["previous"] == {"first_index": -624, "values": drawn[-624:]}        # the generation before
    assert f["next"]["values"] == later[:624]
    assert f["seed"] == {"outputs_before": 1248, "kind": "init_by_array", "key": [0x9094], "python_seed": 0x9094}

    # The step the engine leaves to the solver, done from the journal's own fields: tx 155 is one
    # transmission before the window's first (156), 8 words a key, so its key is the last 8 rewound words.
    before = f["previous"]["values"]
    back = (journal["register_window"]["first_tx"] - 155) * journal["schedule"]["words_per_tx"]
    key = b"".join(w.to_bytes(4, "big") for w in before[len(before) - back:][:8])
    stream = b"".join(hashlib.sha256(key + n.to_bytes(4, "big")).digest() for n in range(2))
    sealed = journal["dispatches"][0]["sealed"]
    assert bytes(a ^ b for a, b in zip(sealed, stream)) == order


def test_solve_reads_the_sweep_copy_writes_where_told_and_finds_nothing_in_other_files(tmp_path):
    cd = tmp_path / "c"
    (cd / "unpacked" / "bundle.zip.unpacked").mkdir(parents=True)
    (cd / "unpacked" / "bundle.zip.unpacked" / "log.json").write_text(json.dumps({"out": W}))
    (cd / "files").mkdir()
    (cd / "files" / "bundle.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    out = tmp_path / "elsewhere"
    res = ma.solve(cd, PROFILE, out=str(out), rewind=4, forward=2)
    assert res.status == "unsure" and res.evidence[0].path == "unpacked/bundle.zip.unpacked/log.json"
    assert str(out / "mt_arrays.json") in res.notes and not (cd / "recon").exists()
    f, = json.loads((out / "mt_arrays.json").read_text())["findings"]
    assert f["previous"]["values"] == OUT[96:100] and f["next"]["values"] == OUT[900:902]

    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "readme.txt").write_text("no numbers here")
    res = ma.solve(plain, PROFILE)
    assert res.status == "none" and not (plain / "recon").exists()
    assert res.notes == "no MT19937 stretch in 0 word lists of 1 files"


# ---- routing and intake ----------------------------------------------------------------------------

def test_a_cbor_handout_and_a_brief_naming_the_generator_route_here(tmp_path):
    from ctf.engines import router
    (tmp_path / "key-unit-journal.cbor").write_bytes(cbor({"a": 1}))
    ids = [h.manifest.id for h in router.route("crypto", "a seized key-schedule journal", tmp_path)]
    assert "toolkits.mt_arrays" in ids
    assert "toolkits.mt_arrays" in [h.manifest.id for h in router.route("misc", "a journal", tmp_path)]
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("plain words")
    assert "toolkits.mt_arrays" not in [h.manifest.id for h in router.route("crypto", "an RSA key", other)]
    assert "toolkits.mt_arrays" not in [h.manifest.id for h in router.route("web", "a journal", tmp_path)]
    ids = [h.manifest.id for h in router.route("crypto", "the service leaks getrandbits(32) values", other)]
    assert "toolkits.mt_arrays" in ids
    ids = [h.manifest.id for h in router.route("misc", "predict the MT19937 outputs", other)]
    assert ids.index("toolkits.mt_arrays") < ids.index("toolkits.prng_recovery")


def test_intake_runs_the_engine_on_a_journal_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    cd, drawn, *_ = _key_wheel(tmp_path)
    (cd / "unpacked").mkdir()
    (cd / "unpacked" / "key-unit-journal.cbor").write_bytes((cd / "files" / "key-unit-journal.cbor").read_bytes())
    hook = G.Guard("hook", (), "test: no child process, no network")
    plan = E.plan(manifest.discover(), "crypto", "a seized key-schedule journal", cd / "unpacked", guard=hook)
    job = next(j for j in plan.jobs if j.engine == "toolkits.mt_arrays")
    assert job.manifest.intake.run == "challenge" and not job.manifest.intake.spawns
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("spooky"), guard=hook, root=REPO, python=sys.executable,
                    challenge_id="9094", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.result_status == "unsure" and run.flags == ()
    f, = json.loads((cd / "recon" / "mt_arrays" / "mt_arrays.json").read_text())["findings"]
    assert f["file"] == "unpacked/key-unit-journal.cbor" and f["previous"]["values"] == drawn[-624:]
    # a challenge with no structured file is not given to the engine at all
    other = tmp_path / "other" / "unpacked"
    other.mkdir(parents=True)
    (other / "notes.md").write_text("words")
    plan = E.plan(manifest.discover(), "crypto", "an RSA key", other, guard=hook)
    assert "toolkits.mt_arrays" not in {j.engine for j in plan.jobs}


# ---- the CLIs --------------------------------------------------------------------------------------

def test_cli_prints_the_findings_and_the_result_json_last(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "out.txt"
    f.write_text("\n".join(str(w) for w in W))
    assert ma.main([str(f), "--rewind", "3", "--forward", "2", "--out", str(tmp_path / "o")]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].startswith(f"{f}: MT19937 outputs: 800 consecutive 32-bit words at $ ")
    assert lines[1] == f"  previous: {OUT[97:100]}" and lines[2] == f"  next: {OUT[900:902]}"
    res = SolverResult.from_json(lines[-1])
    assert res.status == "unsure" and str(tmp_path / "o" / "mt_arrays.json") in res.notes
    assert json.loads((tmp_path / "o" / "mt_arrays.json").read_text())["findings"][0]["previous"]["values"] == OUT[97:100]

    assert ma.main([str(f), "--json"]) == 0
    out = capsys.readouterr().out
    body, last = out.rsplit("\n{", 1)
    whole = json.loads(body[:body.rindex("}") + 1])
    assert whole["findings"][0]["next"]["values"] == OUT[900:1524]
    assert SolverResult.from_json("{" + last).status == "unsure"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["o", "out.txt"]      # no --out: nothing written


def test_cli_refuses_missing_and_oversized_files_and_bad_counts(tmp_path, capsys, monkeypatch):
    f = tmp_path / "out.txt"
    f.write_text("\n".join(str(w) for w in W))
    assert ma.main([str(tmp_path / "nope.json")]) == 2
    assert "no such file" in capsys.readouterr().err
    assert ma.main([str(f), "--rewind", "-1"]) == 2
    assert "rewind" in capsys.readouterr().err
    monkeypatch.setattr(ma, "MAX_FILE", 10)
    assert ma.main([str(f)]) == 2
    assert "not read" in capsys.readouterr().err
    monkeypatch.setattr(ma, "MAX_FILE", 8 << 20)
    plain = tmp_path / "plain.txt"
    plain.write_text("words only")
    assert ma.main([str(plain)]) == 0
    assert SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1]).status == "none"


def _prng(tmp_path, capsys, payload):
    f = tmp_path / "in.json"
    f.write_text(json.dumps(payload))
    code = prng_recovery.main(["mt-rewind", str(f)])
    got = capsys.readouterr()
    return code, (json.loads(got.out) if got.out.strip() else None), got.err


def test_prng_recovery_cli_rewinds_and_fails_closed(tmp_path, capsys):
    code, out, _ = _prng(tmp_path, capsys, {"outputs": OUT[1000:1700], "count": 5})
    assert code == 0 and out == {"candidate": {"previous": OUT[995:1000], "verified_outputs": 76, "verified": True},
                                 "verified": True}
    code, out, _ = _prng(tmp_path, capsys, {"outputs": OUT[1000:1700]})           # default: one generation
    assert out["candidate"]["previous"] == OUT[376:1000]
    code, out, _ = _prng(tmp_path, capsys, {"outputs": X[1000:1700], "count": 2, "tempered": False})
    assert out["candidate"]["previous"] == X[998:1000] and out["verified"] is True
    # a bare window: the rewind is printed, and marked not verified
    code, out, _ = _prng(tmp_path, capsys, {"outputs": OUT[1000:1624], "count": 2})
    assert code == 0 and out["candidate"]["previous"] == OUT[998:1000]
    assert out["candidate"]["verified_outputs"] == 0 and out["verified"] is False
    # words that are not a stream: no candidate
    broken = list(OUT[1000:1700])
    broken[650] ^= 1
    assert _prng(tmp_path, capsys, {"outputs": broken})[1] == {"candidate": None, "verified": False}
    # requests outside the bounds are usage errors that name the bound, never a null candidate
    gen = random.Random(5)
    long = [gen.getrandbits(32) for _ in range(4700)]
    for payload, reason in [
        ({"outputs": OUT[:623]}, "outputs must be a list of 624 to 4096 words"),
        ({"outputs": long[:4097]}, "outputs must be a list of 624 to 4096 words"),
        ({"outputs": {"a": 1}}, "outputs must be a list"),
        ({"outputs": OUT[1000:1623] + [1 << 32]}, "32-bit unsigned"),
        ({"outputs": OUT[1000:1623] + [-1]}, "32-bit unsigned"),
        ({"outputs": OUT[1000:1623] + [True]}, "32-bit unsigned"),
        ({"outputs": OUT[1000:1700], "count": 65537}, "count must be an integer from 1 to 65536"),
        ({"outputs": OUT[1000:1700], "count": 0}, "count must be an integer from 1 to 65536"),
        ({"outputs": OUT[1000:1700], "count": "5"}, "count must be an integer"),
    ]:
        code, out, err = _prng(tmp_path, capsys, payload)
        assert (code, out) == (2, None) and reason in err, payload
    # the bounds themselves are accepted
    code, out, _ = _prng(tmp_path, capsys, {"outputs": long[604:], "count": 65536})
    assert code == 0 and out["verified"] is True and out["candidate"]["verified_outputs"] == 4096 - 624
    assert len(out["candidate"]["previous"]) == 65536 and out["candidate"]["previous"][-604:] == long[:604]
    code, out, _ = _prng(tmp_path, capsys, {"outputs": OUT[1000:1624], "count": 1})
    assert code == 0 and out["candidate"]["previous"] == OUT[999:1000]
    # malformed requests are usage errors
    code, out, err = _prng(tmp_path, capsys, {"outputs": OUT[1000:1700], "tempered": "no"})
    assert code == 2 and out is None and "tempered" in err
    code, out, err = _prng(tmp_path, capsys, {"count": 5})
    assert code == 2 and out is None and "outputs" in err
