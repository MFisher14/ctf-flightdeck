"""B-062: the keyed classical / book-cipher sweep with handout key harvest.

Every handout here is written for this test (a harbour radio net, two made-up songs): nothing is a
real challenge file. Cipher texts are made from plain text the test holds with the library's
encoders, and every reading is compared with that plain text, never with an encoder's output. The
word coverage the sweep ranks by comes from the handout's own words and a short list of common
English words, so the results hold with or without a system dictionary. Budgets are given
explicitly (CPU seconds, far above what the sweeps need) or driven by a step clock: no test bounds
wall time. The intake tests use a fake platform adapter and the repo's real manifests; no network.
"""
from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import event, flagfmt, paths
from ctf.result import SolverResult

REPO = paths.repo_root()
sys.path.insert(0, str(REPO / "solvers" / "common"))
from _shadowed import common_module, module_at  # noqa: E402

C = common_module("classical")
# The path is one string so the coverage report (ctf/engines/coverage.py) counts this file as a test of the engine.
K = module_at(REPO / "solvers/common/keyed_sweep.py", "keyed_sweep_b062")

CSCTF = event.load("csctf")
PINK = event.load("pink")
FF = flagfmt.for_profile(CSCTF)
BIG = {"seconds": 900.0, "wall": 90000.0}       # an explicit budget far above need: the default is for intake


# ---------------------------------------------------------------- fixtures

ROTA = """\
HARBOUR ROTA - working copy
Pier office, 3 March

BERTH  VESSEL        CODENAME  CARGO                    WINDOW       REMARKS
-----  ------------  --------  -----------------------  -----------  --------------------
4      Lady Anne     OSPREY    Timber, deck stowed      05:10-06:40  -
7      Northern Sun  HERON     Sealed crates            08:30-10:15  pier per order
9      Calypso       MARLIN    -                        -            in dry dock until
                                                                     the ninth
12     Grey Wren     PETREL    Mail and stores          13:00-14:20  -
"""

ORDERS = """\
STANDING ORDERS - radio discipline (extract)

2.1  Reports are enciphered with the Vigenere table, letters only. The letter X marks
     a word boundary. The key is the vessel's codename for the day, as listed in
     the harbour rota.
2.2  Message format: time group / cipher text in groups of five letters /
     check group = number of groups.

2.5  Glossary
     VESTIR report     KARGUM cargo      PLOMBA crate(s)
     ADVENIT delivered MOLUM pier        FINIS end
     UNUS 1  DUO 2  TRES 3  QUATTUOR 4  SEPTEM 7
"""

# Made-up report language (the glossary above): X marks a word boundary.
PLAIN1 = "VESTIRXHERONXKARGUMXPLOMBAXQUATTUORXADVENITXMOLUMXTRESXFINIS"      # 60 letters: 12 groups
PLAIN2 = "VESTIRXMARLINXKARGUMXPLOMBAXSEPTEMXADVENITXMOLUMXDUOXFINIS"       # 58 letters: 12 groups, the last short

ENGLISH = "the secret message is hidden under the old house near the water and the answer will follow after the light"
KEYS = """\
LOCKER  WORD      NUMBER
------  --------  ------
A1      ORCHID    27182
B2      LANTERN   31415
C3      TULIPS    16180
"""


def grouped(letters: str, n: int = 5, per_line: int = 9, indent: str = "     ") -> str:
    gs = [letters[i:i + n] for i in range(0, len(letters), n)]
    return "\n".join(indent + " ".join(gs[i:i + per_line]) for i in range(0, len(gs), per_line))


def log(ct1: str, ct2: str, check1: str = "12", check2: str = "11") -> str:
    return ("INTERCEPT LOG - harbour net - 3 March\n\n"
            f"#1   heard 10:21\n     031020\n{grouped(ct1)}\n     {check1}\n\n"
            f"#2   heard 16:34\n     031630\n{grouped(ct2)}\n     {check2}\n")


def put(folder: Path, files: dict) -> Path:
    for rel, data in files.items():
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return folder


def harbour(folder: Path) -> Path:
    ct1 = C.vigenere_encrypt(PLAIN1, "HERON")
    ct2 = C.vigenere_encrypt(PLAIN2, "MARLIN")
    return put(folder, {"01_rota.txt": ROTA, "02_orders.txt": ORDERS, "03_log.txt": log(ct1, ct2)})


def docs(**texts) -> list:
    return [K.Doc(rel, text) for rel, text in texts.items()]


def keys_of(*docs_, **kw) -> dict:
    cts, spans = K.find_ciphertexts(list(docs_))
    return {k.text: k for k in K.harvest_keys(list(docs_), spans, **kw)}


# ---------------------------------------------------------------- the harbour net, end to end

def test_harbour_sweep_reads_both_intercepts_and_ranks_without_picking(tmp_path):
    d = harbour(tmp_path / "ch")
    rep = K.sweep(d, FF, **BIG)
    clean = rep.clean()
    assert [(r.ciphertext, r.cipher, r.key, r.plaintext) for r in clean] == [
        ("03_log.txt#1", "vigenere", "HERON", PLAIN1),
        ("03_log.txt#2", "vigenere", "MARLIN", PLAIN2)]            # both listed; no other key or cipher reads clean
    assert rep.readings[:2] == clean                              # and they lead the ranking
    assert rep.where == "the folder itself" and rep.docs == 3
    one, two = clean
    assert one.check == "check group 12 (the line after the groups) vs 12 groups of 5 counted: ok"
    assert two.check == "check group 11 (the line after the groups) vs 12 groups of 5 counted: MISMATCH"
    assert one.tier == 0 and "column CODENAME" in one.key_source and "01_rota.txt:7" in one.key_source
    assert "The key is the vessel's codename for the day" in one.key_source
    assert one.hits[:4] == ("vestir", "heron", "kargum", "plomba") and one.coverage > 0.8
    assert rep.trials == rep.planned and not rep.cut


def test_a_failed_check_group_sorts_after_a_passing_one_but_stays_listed(tmp_path):
    ct1, ct2 = C.vigenere_encrypt(PLAIN1, "HERON"), C.vigenere_encrypt(PLAIN2, "MARLIN")
    d = put(tmp_path / "ch", {"01_rota.txt": ROTA, "02_orders.txt": ORDERS,
                              "03_log.txt": log(ct1, ct2, check1="15", check2="12")})
    rep = K.sweep(d, FF, **BIG)
    assert [(r.key, "MISMATCH" in r.check) for r in rep.clean()] == [("MARLIN", False), ("HERON", True)]


def test_harbour_result_is_unsure_with_each_clean_reading_as_evidence_and_a_report(tmp_path):
    d = harbour(tmp_path / "ch")
    r = K.solve(d, CSCTF, **BIG)
    assert isinstance(r, SolverResult) and r.status == "unsure" and r.flags == () and r.engine == "common.keyed_sweep"
    assert len(r.evidence) == 2 and [e.path for e in r.evidence] == ["03_log.txt", "03_log.txt"]
    first, second = (e.detail for e in r.evidence)
    assert PLAIN1 in first and "key 'HERON'" in first and "counted: ok" in first
    assert PLAIN2 in second and "key 'MARLIN'" in second and "MISMATCH" in second
    assert "ranked, not picked" in r.notes
    out = d / "recon" / "engines" / "common.keyed_sweep"
    md = (out / "keyed_sweep.md").read_text()
    assert PLAIN1 in md and PLAIN2 in md and "MISMATCH" in md and "not a pick" in md
    assert "Keys by tier: 0 (stated or hinted): 5; 1 (table cell, upper-case or quoted token): " in md
    saved = json.loads((out / "keyed_sweep.json").read_text())
    assert saved["schema"] == 1 and [c["rank"] for c in saved["candidates"][:2]] == [1, 2]
    assert saved["candidates"][0]["plaintext"] == PLAIN1 and saved["candidates"][0]["clean"] is True
    assert [c["check"]["ok"] for c in saved["ciphertexts"] if c["kind"] == "groups"] == [True, False]
    assert {k["key"] for k in saved["keys"]["first"]} >= {"OSPREY", "HERON", "MARLIN", "PETREL"}


def test_a_second_run_does_not_read_its_own_report_as_handout(tmp_path):
    d = harbour(tmp_path / "ch")
    K.solve(d, CSCTF, **BIG)
    rep = K.sweep(d, FF, **BIG)
    assert rep.docs == 3 and len(rep.clean()) == 2


def test_without_the_right_key_in_the_handout_nothing_reads_cleanly(tmp_path):
    ct1 = C.vigenere_encrypt(PLAIN1, "WALRUS")
    d = put(tmp_path / "ch", {"01_rota.txt": ROTA, "02_orders.txt": ORDERS, "03_log.txt": log(ct1, ct1)})
    rep = K.sweep(d, FF, **BIG)
    assert rep.clean() == [] and rep.trials == rep.planned > 100
    r = K.solve(d, CSCTF, **BIG)
    assert r.status == "none" and "cipher text(s), 0 index run(s)" in r.notes and "nothing reads cleanly" in r.notes
    stated = K.sweep(d, FF, key="WALRUS", **BIG)                  # the operator states the key: tried first
    assert [(x.key, x.tier, x.key_source, x.plaintext) for x in stated.clean()][0] == (
        "WALRUS", 0, "given with --opt key", PLAIN1)
    assert stated.keys[0].text == "WALRUS"
    digits = put(tmp_path / "g", {"msg.txt": "MESSAGE 4\n" + grouped(C.vigenere_encrypt(C.letters(ENGLISH), "dbebf").upper())})
    assert K.sweep(digits, FF, **BIG).clean() == []
    (g,) = K.sweep(digits, FF, key=[31415], **BIG).clean()         # a number given as the key: Gronsfeld
    assert (g.cipher, g.key, C.letters(g.plaintext)) == ("gronsfeld", "31415", C.letters(ENGLISH))


# ---------------------------------------------------------------- cipher texts

def test_group_block_carries_its_groups_context_and_check_group():
    (ct,), spans = K.find_ciphertexts(docs(**{"log.txt": log("ABCDE" * 12, "AB")}))
    assert (ct.id, ct.doc, ct.line, ct.kind, ct.groups, ct.group_len) == ("log.txt#1", "log.txt", 5, "groups", 12, 5)
    assert ct.text == " ".join(["ABCDE"] * 12) and ct.letters == 60
    assert ct.context == ("#1   heard 10:21", "031020", "12") and ct.label == "#1   heard 10:21"
    assert ct.check == {"stated": 12, "counted": 12, "ok": True, "where": "the line after the groups"}
    assert spans == {"log.txt": {4, 5}}                           # the two lines of groups, nothing else


def test_a_short_last_group_is_counted_and_ends_the_block():
    text = "AAAAA BBBBB CCCCC\nDDDDD EE\nFFFFF GGGGG HHHHH IIIII\n5\n"
    one, two = K.group_blocks(text.split("\n"))
    assert one == (0, 2, ["AAAAA", "BBBBB", "CCCCC", "DDDDD", "EE"], 5)
    assert two == (2, 3, ["FFFFF", "GGGGG", "HHHHH", "IIIII"], 5)
    cts, _ = K.find_ciphertexts(docs(**{"m.txt": text}))
    assert cts[0].check is None and cts[0].check_line() == "5 groups of 5, no check group stated"
    assert cts[1].check["stated"] == 5 and cts[1].check["ok"] is False


def test_check_group_named_in_the_preamble():
    text = "MSG 7 GR 6\nQWERT YUIOP ASDFG HJKLZ XCVBN MQ\n\nafter\n"
    (ct,), _ = K.find_ciphertexts(docs(**{"m.txt": text}))
    assert ct.check == {"stated": 6, "counted": 6, "ok": True, "where": "the preamble"}


@pytest.mark.parametrize("line", [
    "BERTH  VESSEL  CODENAME  CARGO",        # a header: unequal lengths
    "ALPHA BRAVO DELTA",                      # three groups: under the minimum
    "Alpha Bravo Delta Gamma Omega",          # mixed case
    "ALPHA BRAVO DELTA gamma omega",          # two cases in one line
    "AB CD EF GH IJ KL MN OP",                # groups of two
    "ALPHA BRAV0 DELTA GAMMA OMEGA",          # a digit
    "ABCDEFGHIJK ABCDEFGHIJK ABCDEFGHIJK ABCDEFGHIJK",   # groups of eleven
    "AAA BBB CCC D",                          # four groups, ten letters: under the letter minimum
    "ALPHA BRAVO DELTA GAMMA OMEGAS",         # the last group longer than the rest
])
def test_lines_that_are_not_group_blocks(line):
    assert K.group_blocks([line]) == []


def test_a_one_word_line_does_not_open_a_block_and_a_change_of_case_ends_one():
    assert K.group_blocks(["TITLE", "ABCDE FGHIJ KLMNO PQRST"]) == [(1, 2, ["ABCDE", "FGHIJ", "KLMNO", "PQRST"], 5)]
    two = K.group_blocks(["ABCDE FGHIJ KLMNO PQRST", "abcde fghij klmno pqrst"])
    assert [(a, b) for a, b, _g, _n in two] == [(0, 1), (1, 2)]


def test_the_smallest_block_and_lower_case_groups_are_taken():
    assert K.group_blocks(["AAA BBB CCC DDD"]) == [(0, 1, ["AAA", "BBB", "CCC", "DDD"], 3)]
    assert K.group_blocks(["abcde fghij klmno pqrst"])[0][2] == ["abcde", "fghij", "klmno", "pqrst"]
    assert len(K.group_blocks(["ABCDEFGHIJ"] * 1 + ["ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ"])) == 1


def test_labelled_value_is_a_cipher_text_and_a_short_one_is_not():
    text = "Ciphertext: Wkh vhfuhw\nenc = 'abc'\nnote: Wkh vhfuhw phvvdjh\n"
    cts, spans = K.find_ciphertexts(docs(**{"m.txt": text}))
    assert [(c.id, c.kind, c.line, c.text) for c in cts] == [("m.txt#1", "labelled", 1, "Wkh vhfuhw")]
    assert spans == {"m.txt": {0}}


def test_a_file_that_is_not_prose_is_taken_whole_but_prose_and_tables_are_not():
    enc = C.vigenere_encrypt(ENGLISH.capitalize() + ".", "LANTERN")
    table = "ID  CODE\n--  -------\n1   ZORBLAT\n2   KVINTOS\n3   MEPHARI\n4   DRUMIXA\n"
    assert K._cipherlike(table) and not K._cipherlike(ENGLISH) and not K._cipherlike("Zorblat kvintos mepha")
    assert K._cipherlike("Zorblat kvintos mephar")                # twenty letters: the smallest unmarked text
    assert K._cipherlike("zq" * (K.WHOLE_MAX // 2)) and not K._cipherlike("zq" * (K.WHOLE_MAX // 2) + " z")   # too long
    cts, spans = K.find_ciphertexts(docs(**{"note.enc": enc + "\n", "readme.txt": ENGLISH + "\n", "keys.txt": table}))
    assert [(c.id, c.kind, c.text) for c in cts] == [("note.enc#whole", "whole", enc)]
    assert spans == {}                                            # a whole file stays a key and word source


def test_a_cipher_paragraph_under_a_title_is_taken_on_its_own(tmp_path):
    enc = C.vigenere_encrypt(ENGLISH, "LANTERN")
    d = put(tmp_path / "ch", {"message.txt": f"Xqzv plomr wvu\n\n{enc}\n\nBq trn glomf hjzk dfghjkw\n", "keys.txt": KEYS})
    rep = K.sweep(d, FF, **BIG)
    # The 12-letter title is under the minimum for an unmarked text; the 21-letter line is taken.
    assert [c.id for c in rep.ciphertexts] == ["message.txt#whole", "message.txt#para3", "message.txt#para5"]
    (r,) = rep.clean()                    # the title's letters shift the key under the whole file: only the paragraph reads
    assert (r.ciphertext, r.cipher, r.key, r.plaintext) == ("message.txt#para3", "vigenere", "LANTERN", ENGLISH)


def test_more_cipher_texts_than_the_cap_are_named_not_dropped_silently(monkeypatch):
    monkeypatch.setattr(K, "MAX_CIPHERTEXTS", 2)
    text = "\n\n".join(f"ct: {'QWERTYUIOP'[i:] + 'ASDFGH'}" for i in range(4))
    notes = []
    cts, _ = K.find_ciphertexts(docs(**{"m.txt": text}), notes=notes)
    assert [c.id for c in cts] == ["m.txt#1", "m.txt#2"]
    assert notes == ["4 cipher texts found: only the first 2 are swept (not swept: m.txt#3, m.txt#4)"]


def test_only_note_like_files_are_taken_whole_or_by_paragraph():
    enc = C.vigenere_encrypt(ENGLISH, "LANTERN")
    names = ["a.py", "b.json", "c.html", "d.csv", "e.log", "note", "g.TXT", "h.enc", "i.md"]
    cts, _ = K.find_ciphertexts(docs(**{n: enc + "\n" for n in names}))
    assert [c.id for c in cts] == ["note#whole", "g.TXT#whole", "h.enc#whole", "i.md#whole"]
    marked, _ = K.find_ciphertexts(docs(**{"a.py": f"ciphertext: {enc}\n"}))      # a marked one counts anywhere
    assert [c.kind for c in marked] == ["labelled"]


def test_more_unmarked_texts_than_the_cap_are_named(monkeypatch):
    monkeypatch.setattr(K, "LOOSE_MAX", 2)
    enc = C.vigenere_encrypt(ENGLISH, "LANTERN")
    notes = []
    cts, _ = K.find_ciphertexts(docs(**{f"{n}.txt": enc + "\n" for n in "abc"}), notes=notes)
    assert [c.id for c in cts] == ["a.txt#whole", "b.txt#whole"]
    assert notes == ["3 files or paragraphs do not read as prose: only the first 2 are swept (not swept: c.txt#whole)"]


GLOSSARY = "ZORBLAT crate\nKVINTO pier\nMEPHAR cargo\nDRUMIX end\nVELTRO report\nSANQUI north\n"
PSEUDO = "zorblat kvinto mephar drumix veltro sanqui kvinto zorblat mephar veltro"      # 62 letters, no English


def test_unmarked_text_that_reads_as_handout_words_already_is_not_swept(tmp_path):
    # Not prose by the dictionary, but every word is in the glossary beside it: a key that barely changes
    # the text (the keyword ABD swaps two letters) would read it "cleanly".
    d = put(tmp_path / "ch", {"note.txt": PSEUDO + "\n", "glossary.txt": GLOSSARY, "keys.txt": KEYS + "D4      ABD       1\n"})
    assert K._cipherlike(PSEUDO)
    rep = K.sweep(d, FF, **BIG)
    assert rep.ciphertexts == [] and rep.trials == 0
    assert rep.notes[-1] == ("2 unmarked text(s) read as words as they stand and are not swept: "
                             "glossary.txt#whole, note.txt#whole")
    assert K.result_of(rep, FF).status == "none"


def test_a_reading_must_beat_the_text_as_it_stands_to_be_clean(tmp_path):
    d = put(tmp_path / "ch", {"note.txt": f"ciphertext: {PSEUDO}\n", "glossary.txt": GLOSSARY,
                              "keys.txt": KEYS + "D4      ABD       1\n"})
    rep = K.sweep(d, FF, **BIG)
    (ct,) = [c for c in rep.ciphertexts if c.kind == "labelled"]
    assert ct.base == 1.0                                         # a marked text is swept whatever it reads as
    near = [r for r in rep.readings if r.key == "ABD" and r.cipher == "keyword"]
    assert near and near[0].coverage >= K.need(62) and not near[0].clean      # reads, but no better than no key
    assert rep.clean() == []


def test_plain_words_are_not_tried_on_unmarked_text_once_they_are_many(tmp_path, monkeypatch):
    enc = C.vigenere_encrypt(ENGLISH, "lantern")
    prose = "we lit the lantern and left before the light came over the water\n"
    loose = put(tmp_path / "loose", {"note.enc": enc + "\n", "story.txt": prose})
    marked = put(tmp_path / "marked", {"note.enc": f"ciphertext: {enc}\n", "story.txt": prose})
    assert [r.key for r in K.sweep(loose, FF, **BIG).clean()] == ["lantern"]         # few words: all tried
    monkeypatch.setattr(K, "LOOSE_WORDS", 3)
    rep = K.sweep(loose, FF, **BIG)
    assert rep.clean() == [] and rep.trials == rep.planned
    assert "more than 3 plain words in the handout: on unmarked text only stated" in " ".join(rep.notes)
    upper = put(tmp_path / "upper", {"note.enc": enc + "\n", "story.txt": prose.replace("lantern", "LANTERN")})
    assert [(r.key, r.tier) for r in K.sweep(upper, FF, **BIG).clean()] == [("LANTERN", 1)]
    kept = K.sweep(marked, FF, **BIG)                              # a marked text still gets every word
    assert [r.key for r in kept.clean()] == ["lantern"] and not any("plain words" in n for n in kept.notes)


def test_a_cipher_text_given_by_hand_is_swept_first_and_a_scrap_is_refused(tmp_path):
    d = put(tmp_path / "ch", {"keys.txt": KEYS})
    enc = C.vigenere_encrypt(ENGLISH, "ORCHID")
    rep = K.sweep(d, FF, ciphertext=[enc, "ab"], **BIG)
    assert [c.id for c in rep.ciphertexts] == ["stated#1"]
    assert rep.notes[0] == "--opt ciphertext #2: under 6 letters, not swept"
    assert [(r.key, r.plaintext) for r in rep.clean()] == [("ORCHID", ENGLISH)]
    assert K.result_of(rep, FF).evidence[0].path is None


# ---------------------------------------------------------------- tables

def test_ruled_table_is_cut_by_column_position():
    (t,) = K.find_tables(ROTA.split("\n"))
    assert t.kind == "ruled" and t.header == ["BERTH", "VESSEL", "CODENAME", "CARGO", "WINDOW", "REMARKS"]
    assert t.header_line == 4 and [n for n, _ in t.rows] == [6, 7, 8, 9, 10]
    assert t.rows[1][1] == ["7", "Northern Sun", "HERON", "Sealed crates", "08:30-10:15", "pier per order"]
    assert t.rows[3][1] == ["", "", "", "", "", "the ninth"]      # a continuation row keeps its column


def test_piped_table_drops_its_rule_row():
    text = "| word | use |\n|------|-----|\n| LEMON | key |\n| PEACH | spare |\n"
    (t,) = K.find_tables(text.split("\n"))
    assert (t.kind, t.header, [c for _, c in t.rows]) == ("piped", ["word", "use"], [["LEMON", "key"], ["PEACH", "spare"]])


@pytest.mark.parametrize("delim", ["\t", ",", ";"])
def test_delimited_table(delim):
    text = "\n".join(delim.join(r) for r in (["name", "word"], ["a", "LEMON"], ["b", "PEACH"])) + "\n"
    (t,) = K.find_tables(text.split("\n"))
    assert (t.kind, t.header, t.rows) == ("delimited", ["name", "word"], [(2, ["a", "LEMON"]), (3, ["b", "PEACH"])])


def test_aligned_table_has_no_header_and_two_rows_are_not_a_table():
    text = "KORZO   small arms\nMEZHA   rations and water\nSNIPO   jamming set\n\nONE   a\nTWO   b\n"
    (t,) = K.find_tables(text.split("\n"))
    assert (t.kind, t.header, [c[0] for _, c in t.rows]) == ("aligned", [], ["KORZO", "MEZHA", "SNIPO"])


def test_cipher_text_lines_are_never_table_rows():
    lines = ["a  b", "c  d", "e  f", "g  h"]
    assert len(K.find_tables(lines)[0].rows) == 4
    assert K.find_tables(lines, skip={1}) == []                    # the run is broken: one row and two rows


# ---------------------------------------------------------------- key harvest

def test_a_column_named_by_a_key_sentence_goes_first_and_says_why():
    ks = keys_of(*docs(**{"rota.txt": ROTA, "orders.txt": ORDERS}))
    for name in ("OSPREY", "HERON", "MARLIN", "PETREL"):
        assert ks[name].tier == 0 and ks[name].why.startswith("column CODENAME, named by the key sentence")
    assert ks["HERON"].sources[0] == "rota.txt:7"
    assert ks["Calypso"].tier == 0                                # the sentence names the vessel column too
    anne, crates = ks["Lady Anne"], ks["Sealed crates"]           # a cell of several words is one key, a tier lower
    assert (anne.norm, anne.tier, anne.why.endswith(", the whole cell")) == ("ladyanne", 1, True)
    assert (crates.norm, crates.tier, crates.why) == ("sealedcrates", 2, "column CARGO of a ruled table, the whole cell")
    assert (ks["Timber"].tier, ks["PLOMBA"].tier, ks["discipline"].tier) == (2, 1, 2)
    assert ks["CODENAME"].why == "table header" and ks["CODENAME"].sources == ["rota.txt:4", "orders.txt:4"]
    without = keys_of(*docs(**{"rota.txt": ROTA}))
    assert without["HERON"].tier == 1 and without["HERON"].why == "column CODENAME of a ruled table"


def test_a_plural_header_answers_to_the_singular_in_the_sentence():
    table = "id  CALLSIGNS\n--  ---------\n1   KESTREL\n2   GANNET\n"
    ks = keys_of(*docs(**{"t.txt": table, "o.txt": "The key is the crew's callsign for the day.\n"}))
    assert ks["KESTREL"].tier == 0 and ks["GANNET"].tier == 0


def test_stated_keys_are_tier_zero_but_a_sentence_about_the_key_states_none():
    text = ("key: LEMON\npassword = \"tulip7\"\nThe key is the vessel's codename.\nthe key is ORCHID today\n"
            "primer was kestrel\nthe passphrase is 'walnut' again\n")
    ks = keys_of(*docs(**{"n.txt": text}))
    assert (ks["walnut"].tier, ks["walnut"].why) == (0, "stated key")           # quoted after "is"
    assert (ks["LEMON"].tier, ks["LEMON"].why, ks["LEMON"].sources) == (0, "stated key", ["n.txt:1"])
    assert ks["tulip7"].tier == 0 and ks["ORCHID"].tier == 0
    assert ks["The"].tier == 2 and ks["kestrel"].tier == 2          # a plain word after "is" is not a stated key


def test_tokens_by_kind_and_tier():
    ks = keys_of(*docs(**{"n.txt": "Meet at DOCK seven, bring \"the green lamp\" and 4711 or 9.\n"}))
    assert (ks["DOCK"].tier, ks["DOCK"].why) == (1, "upper-case token")
    assert (ks["seven"].tier, ks["seven"].kind) == (2, "alpha")
    assert (ks["the green lamp"].tier, ks["the green lamp"].norm, ks["the green lamp"].why) == (1, "thegreenlamp", "quoted")
    assert (ks["4711"].kind, ks["4711"].norm, ks["4711"].tier) == ("digits", "4711", 2)
    assert "9" not in ks and "at" not in ks                       # one digit, two letters: not keys
    assert ks["n"].why == "file name" if "n" in ks else True


def test_keys_that_cannot_be_keys_are_left_out():
    ring = K.KeyRing()
    for text, digits in (("ab", False), ("AAAA", False), ("x" * 41, False), ("7", True), ("000", True),
                         ("1" * 17, True), ("abc", False), ("12", True), ("a" * 20 + "b" * 20, False)):
        ring.add(text, 2, "t", digits=digits)
    assert [(k.kind, k.norm) for k in ring.ordered()] == [("alpha", "abc"), ("digits", "12"),
                                                          ("alpha", "a" * 20 + "b" * 20)]


def test_cipher_text_is_not_harvested_for_keys_or_words():
    ds = docs(**{"log.txt": log("QWERT" * 12, "ZXCVB" * 12, check2="12")})
    cts, spans = K.find_ciphertexts(ds)
    ks = {k.text for k in K.harvest_keys(ds, spans)}
    assert "QWERT" not in ks and "ZXCVB" not in ks and "INTERCEPT" in ks and "heard" in ks
    words = K.handout_words(ds, spans)
    assert "qwert" not in words and "intercept" in words and "harbour" in words


def test_one_key_per_word_with_its_best_tier_and_every_place_it_was_seen():
    ks = keys_of(*docs(**{"a.txt": "we sail with heron at dawn\n", "b.txt": KEYS.replace("ORCHID", "HERON ")}))
    k = ks["HERON"]
    assert (k.tier, k.why, k.sources) == (1, "column WORD of a ruled table", ["b.txt:3", "a.txt:1"])
    assert "heron" not in ks                                      # the same key, not a second one


def test_more_keys_than_the_cap_is_said(monkeypatch):
    monkeypatch.setattr(K, "MAX_KEYS", 5)
    notes = []
    ks = K.harvest_keys(docs(**{"a.txt": "alpha bravo charlie delta echo foxtrot golf hotel\n"}), notes=notes)
    assert len(ks) == 5 and notes == ["more than 5 candidate keys: the rest are not tried"]


def test_strings_of_a_binary_sibling_are_last_tier_keys_and_can_open_the_text(tmp_path):
    blob = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR" + bytes(range(13)) + b"\x00\x00\x00\x10tEXtComment\x00LANTERN\x00\xff\xfe\x01"
    enc = C.vigenere_encrypt(ENGLISH, "LANTERN")
    d = put(tmp_path / "ch", {"photo.png": blob, "note.txt": f"ciphertext: {enc}\n"})
    rep = K.sweep(d, FF, **BIG)
    assert rep.binaries == 1
    key = {k.text: k for k in rep.keys}["LANTERN"]
    assert (key.tier, key.why, key.sources) == (3, "string of a binary file", ["photo.png"])
    assert [(r.key, r.cipher, r.plaintext) for r in rep.clean()] == [("LANTERN", "vigenere", ENGLISH)]


# ---------------------------------------------------------------- scoring

@pytest.mark.parametrize("n,want", [(5, float("inf")), (6, 0.8), (29, 0.8), (30, 0.65), (59, 0.65), (60, 0.5), (600, 0.5)])
def test_shorter_readings_need_more_coverage(n, want):
    assert K.need(n) == want


def test_scorer_covers_with_handout_words_and_names_them_in_order():
    s = K.Scorer({"vestir", "kargum", "plomba", "duo", "xy"})
    cover, words, hits = s.explain("VESTIRXKARGUMXDUOXPLOMBAXKARGUM")
    assert words == ["vestir", "kargum", "duo", "plomba", "kargum"] and hits == ["vestir", "kargum", "plomba"]
    assert cover == round(27 / 31, 4) == s.cover("vestir-x-kargum x duo x plomba x kargum")
    assert K.Scorer().cover("VESTIRXKARGUMXDUOXPLOMBAXKARGUM") < 0.3          # the same text without the glossary
    assert s.cover("") == 0.0 and s.explain("12 34") == (0.0, [], [])


def test_cribs_given_by_hand_make_a_reading_clean(tmp_path):
    plain = "ZORBLATXMEPHARXKVINTOXZORBLATXDRUMIXMEPHARXKVINTOXZORBLATXMEPHARXDRUMI"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "msg.txt": "MESSAGE 4\n" + grouped(C.vigenere_encrypt(plain, "TULIPS"))})
    assert K.sweep(d, FF, **BIG).clean() == []                    # the right key, but no word the sweep knows
    (r,) = K.sweep(d, FF, crib=["zorblat", "MEPHAR", "kvinto", "drumi"], **BIG).clean()
    assert (r.key, r.plaintext, r.hits) == ("TULIPS", plain, ("zorblat", "mephar", "kvinto", "drumi"))


def test_a_host_without_a_system_dictionary_is_said_in_the_notes(tmp_path, monkeypatch):
    d = harbour(tmp_path / "ch")
    monkeypatch.setattr(K, "has_system_dictionary", lambda: True)
    assert not any("system dictionary" in n for n in K.sweep(d, FF, **BIG).notes)
    monkeypatch.setattr(K, "has_system_dictionary", lambda: False)
    rep = K.sweep(d, FF, **BIG)
    assert rep.notes[0].startswith("no system dictionary on this host: readings are scored on the handout's own words")
    assert len(rep.clean()) == 2                                  # the handout's glossary still reads both


def test_a_tie_goes_to_the_longer_word():
    assert K.Scorer({"hum", "ming", "humming"}).explain("humming") == (1.0, ["humming"], ["humming"])


def test_ranking_order_flags_then_clean_then_check_then_coverage_then_hits_then_tier():
    def r(**kw):
        return K.Reading("c#1", "vigenere", "k", "s", kw.pop("tier", 1), "p", **kw)
    order = [r(flags=("F{x}",), coverage=0.1), r(clean=True, coverage=0.55), r(clean=True, coverage=0.9, check="x MISMATCH"),
             r(coverage=0.7), r(coverage=0.6, hits=("a", "b")), r(coverage=0.6, hits=("a",), tier=0),
             r(coverage=0.6, hits=("a",), tier=2)]
    assert sorted(reversed(order), key=K.Reading.rank_key) == order


def test_crib_words_count_as_handout_words():
    s = K.Scorer(set(), cribs=["Zorblat", "qi"])
    assert s.explain("zorblatqizorblat") == (round(14 / 16, 4), ["zorblat", "zorblat"], ["zorblat"])


def test_a_reading_that_opens_with_no_words_is_not_scored_further():
    s = K.Scorer({"vestir", "kargum"})
    tail = "vestirkargum" * 10
    assert s.cover("q" * 48 + tail) == 0.0                        # the probe: 48 letters, none covered
    assert s.cover("q" * 30 + tail) > 0.7                         # words inside the probe: scored in full
    assert s.cover("q" * 36 + "vestirkargum") == 0.25             # 48 letters exactly: no probe, the full score


def test_a_leet_flag_body_reads_as_words_and_noise_does_not():
    s = K.Scorer()
    assert s.reads("th3_s3cr3t_m3554g3") and s.reads("hidden_under_the_house")
    assert not s.reads("qzvkx_wpfjq_zzkxv") and not s.reads("the") and not s.reads("")


# ---------------------------------------------------------------- the ciphers

def _playfair_plain() -> str:
    text = C.letters("the secret message is under the old house near the water")
    pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
    assert len(text) % 2 == 0 and "j" not in text and all(a != b for a, b in pairs)   # so the reading is the text itself
    return text


CASES = {
    "vigenere": ("LANTERN", lambda p, k: C.vigenere_encrypt(p, k), None),
    "beaufort": ("LANTERN", lambda p, k: C.vigenere_encrypt(p, k, "beaufort"), None),
    "variant": ("LANTERN", lambda p, k: C.vigenere_encrypt(p, k, "variant"), None),
    "autokey": ("LANTERN", lambda p, k: C.autokey_encrypt(p, k), None),
    "porta": ("LANTERN", lambda p, k: C.porta(p, k), None),
    "keyword": ("LANTERN", lambda p, k: C.substitution_encrypt(p, C.keyword_alphabet(k)), None),
    "playfair": ("LANTERN", lambda p, k: C.playfair_encrypt(p, k), _playfair_plain),
    "columnar": ("LANTERN", lambda p, k: C.columnar_encrypt(p, k), None),
    "gronsfeld": ("31415", lambda p, k: C.vigenere_encrypt(p, "".join(chr(97 + int(c)) for c in k)), None),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_each_keyed_cipher_is_read_with_the_key_from_the_table(tmp_path, name):
    key, encrypt, plain_of = CASES[name]
    plain = plain_of() if plain_of else C.letters(ENGLISH)
    enc = encrypt(plain, key).upper()
    assert C.letters(enc) != plain
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "msg.txt": f"MESSAGE 4\n{grouped(enc)}\n"})
    rep = K.sweep(d, FF, **BIG)
    (r,) = rep.clean()                                            # one reading, under this cipher and no other
    assert (r.cipher, r.key, C.letters(r.plaintext)) == (name, key, plain)
    assert r.key_source.startswith("keys.txt:4 (column ") and rep.readings[0] is r


def test_ciphers_that_need_a_likely_key_are_not_tried_with_every_word(tmp_path):
    plain = _playfair_plain()
    enc = grouped(C.playfair_encrypt(plain, "lantern").upper())
    prose = put(tmp_path / "a", {"n.txt": "we lit the lantern and left\n", "msg.txt": f"MESSAGE 4\n{enc}\n"})
    assert K.sweep(prose, FF, **BIG).clean() == []                # a plain word: Playfair is not tried with it
    table = put(tmp_path / "b", {"n.txt": "we lit the LANTERN and left\n", "msg.txt": f"MESSAGE 4\n{enc}\n"})
    assert [(r.cipher, r.key) for r in K.sweep(table, FF, **BIG).clean()] == [("playfair", "LANTERN")]
    vig = grouped(C.vigenere_encrypt(C.letters(ENGLISH), "lantern").upper())
    word = put(tmp_path / "c", {"n.txt": "we lit the lantern and left\n", "msg.txt": f"MESSAGE 4\n{vig}\n"})
    assert [(r.cipher, r.key, r.tier) for r in K.sweep(word, FF, **BIG).clean()] == [("vigenere", "lantern", 2)]


def test_keys_that_leave_the_text_as_it_is_are_not_readings(tmp_path):
    assert K._keyword("hello", "abc") is None and K._keyword("hello", "zebra") == C.substitution_decrypt(
        "hello", C.keyword_alphabet("zebra"))
    assert K._columnar("thesecretmessage", "ace") is None          # columns already in order
    assert K._columnar("abc", "zebra") is None                    # a key as long as the text
    assert K._columnar(C.columnar_encrypt("thesecretmessage", "zebra"), "zebra") == "thesecretmessage"
    assert K._playfair("abc", "zebra") is None                    # an odd number of letters
    d = put(tmp_path / "ch", {"n.txt": "ACE ABC BEST\n", "msg.txt": f"ciphertext: {ENGLISH}\n"})
    rep = K.sweep(d, FF, ciphers=["keyword", "columnar"], **BIG)
    assert rep.clean() == [] and rep.trials > 0                   # plain text in, and no "reading" of it out


def test_the_same_reading_from_two_keys_is_listed_once(tmp_path):
    enc = grouped(C.vigenere_encrypt(C.letters(ENGLISH), "lantern").upper())
    d = put(tmp_path / "ch", {"n.txt": "LANTERN and LANTERNLANTERN\n", "msg.txt": f"MESSAGE 4\n{enc}\n"})
    (r,) = K.sweep(d, FF, **BIG).clean()
    assert (r.key, r.also) == ("LANTERN", ["vigenere key LANTERNLANTERN"])


def test_only_the_named_ciphers_run_and_an_unknown_name_is_refused(tmp_path):
    d = put(tmp_path / "ch", {"keys.txt": KEYS,
                              "msg.txt": "MESSAGE 4\n" + grouped(C.vigenere_encrypt(C.letters(ENGLISH), "lantern").upper())})
    assert K.sweep(d, FF, ciphers="beaufort", **BIG).clean() == []
    assert [r.cipher for r in K.sweep(d, FF, ciphers=["beaufort", "vigenere"], **BIG).clean()] == ["vigenere"]
    with pytest.raises(ValueError, match="unknown cipher.*rot99.*known: vigenere"):
        K.sweep(d, FF, ciphers=["rot99"], **BIG)


# Common words only, so the poem reads as prose (not as a cipher text of its own) on a host with no dictionary too.
POEM = ("the old man came down to the water every day\n"
        "we live in a small house near the side of the land\n"
        "my mother and father first came here a long time after\n"
        "people would turn and look when the light went high over the earth\n"
        "every animal and every boy must find a home before the long line\n"
        "what we think and what we say may change the world again and again\n"
        "little by little the great picture will show where we must go\n")


def test_running_key_from_a_sibling_text(tmp_path):
    poem = POEM
    plain = C.letters(ENGLISH)
    stream = C.letters("".join(poem.split("\n")[2:]))             # the key starts at line 3
    enc = grouped(C.vigenere_encrypt(plain, stream[:len(plain)]).upper())
    d = put(tmp_path / "ch", {"poem.txt": poem, "msg.txt": f"MESSAGE 4\n{enc}\n"})
    (r,) = K.sweep(d, FF, **BIG).clean()
    assert (r.cipher, r.key, C.letters(r.plaintext)) == ("running-key", "poem.txt from line 3", plain)
    assert K.sweep(d, FF, ciphers=[n for n in K.CIPHER_NAMES if n != "running-key"], **BIG).clean() == []
    # Only a start that leaves as many letters as the text has is tried (counted from the fixture itself).
    total, at, fits = len(C.letters(poem)), 0, 0
    for w in poem.split():
        fits += total - at >= len(plain)
        at += len(C.letters(w))
    only = K.sweep(d, FF, ciphers=["running-key"], **BIG)
    assert only.trials == only.planned == fits and 0 < fits < len(poem.split())


def test_running_key_starts_are_capped(tmp_path, monkeypatch):
    plain = C.letters(ENGLISH)
    enc = grouped(C.vigenere_encrypt(plain, C.letters("".join(POEM.split("\n")[2:]))[:len(plain)]).upper())
    d = put(tmp_path / "ch", {"poem.txt": POEM, "msg.txt": f"MESSAGE 4\n{enc}\n"})
    assert [r.key for r in K.sweep(d, FF, ciphers=["running-key"], **BIG).clean()] == ["poem.txt from line 3"]
    monkeypatch.setattr(K, "RUNNING_MAX", 2)                      # lines 1 and 2 only
    capped = K.sweep(d, FF, ciphers=["running-key"], **BIG)
    assert capped.clean() == [] and capped.trials == 2


def test_running_key_can_start_at_a_word_inside_a_line():
    c = K.Corpus("p.txt", "Grey water, under\n\nthe keel")
    stream, starts = c.stream()
    assert stream == "greywaterunderthekeel"
    assert starts == [(0, "line 1"), (14, "line 3"), (4, "line 1 word 'water'"), (9, "line 1 word 'under'"),
                      (17, "line 3 word 'keel'")]


# ---------------------------------------------------------------- flags and the result

FLAG = "CSCTF{the_secret_is_hidden_under_the_old_house}"


def test_one_flag_in_a_clean_reading_is_solved(tmp_path):
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(FLAG, 'LANTERN')}\n"})
    r = K.solve(d, CSCTF, **BIG)
    assert (r.status, r.flags) == ("solved", (FLAG,))
    assert "vigenere with key 'LANTERN' (keys.txt:4" in r.evidence[0].detail and r.evidence[0].path == "c.txt"


def test_a_flag_whose_body_is_noise_is_only_a_candidate(tmp_path):
    noise = "CSCTF{qzvkx_wpfjq_zzkxv}"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(noise, 'LANTERN')}\n"})
    r = K.solve(d, CSCTF, **BIG)
    assert r.status == "candidate" and r.flags[0] == noise          # never solved on a wrapper alone
    assert all(f.startswith("CSCTF{") for f in r.flags) and r.evidence
    one = K.solve(d, CSCTF, ciphers=["vigenere"], **BIG)           # one flag, one reading: still not solved
    assert (one.status, one.flags) == ("candidate", (noise,)) and "does not read as words" in one.notes
    # Keys that share the right key's start all get the wrapper right: only the best few are listed.
    more = put(tmp_path / "more", {"keys.txt": KEYS + "D4      LANTERNS  1\nE5      LANTERNA  2\nF6      LANTERNED 3\n",
                                   "c.txt": f"ciphertext: {C.vigenere_encrypt(noise, 'LANTERN')}\n"})
    rep = K.sweep(more, FF, ciphers=["vigenere"], **BIG)
    assert len({f for r in rep.readings for f in r.flags}) == 4
    assert len(K.result_of(rep, FF).flags) == K.LOOSE_FLAGS == 3


def test_a_leet_flag_body_that_reads_is_solved(tmp_path):
    leet = "CSCTF{th3_s3cr3t_m3554g3}"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(leet, 'TULIPS')}\n"})
    r = K.solve(d, CSCTF, **BIG)
    assert (r.status, r.flags) == ("solved", (leet,))


def test_a_hex_flag_body_is_proof_too(tmp_path):
    hexed = "CSCTF{0a1b2c3d4e5f60718293a4b5}"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(hexed, 'ORCHID')}\n"})
    r = K.solve(d, CSCTF, **BIG)
    assert (r.status, r.flags) == ("solved", (hexed,))
    s = K.Scorer()
    assert s.reads("0a1b-2c3d-4e5f-6071") and not s.reads("0a1b2c3d4e5f607") and not s.reads("0123456789012345a1b2c")


def test_a_short_wrapper_that_chance_explains_is_left_out(tmp_path, monkeypatch):
    # CSCTF's profile also takes the three-letter CTF{...}: over thousands of decrypts some wrong key lands on it.
    noise = "ctf{qzvkx_wpfjq_zzkxv}"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(noise, 'LANTERN')}\n"})
    rep = K.sweep(d, FF, ciphers=["vigenere"], **BIG)
    assert rep.trials < 0.01 * 26 ** 3                            # few decrypts: three letters are not chance yet
    r = K.result_of(rep, FF)
    assert (r.status, r.flags) == ("candidate", ("CTF{qzvkx_wpfjq_zzkxv}",))
    rep.trials = 400                                              # the same reading after 400 decrypts: 0.02 expected
    r = K.result_of(rep, FF)
    assert r.status == "none" and r.flags == ()
    assert "1 flag-shaped reading(s) that do not read as words left out: over 400 decrypts" in r.notes
    assert K._wrapper_letters("CSCTF{x}") == 5 and K._wrapper_letters("ab1_c{d}") == 3 and K._wrapper_letters("abc") == 3
    words = "ctf{the_secret_is_hidden_under_the_old_house}"       # one that reads is kept however many decrypts
    w = put(tmp_path / "w", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(words, 'LANTERN')}\n"})
    rep = K.sweep(w, FF, ciphers=["vigenere"], **BIG)
    rep.trials = 10 ** 6
    assert K.result_of(rep, FF).status == "solved"


def test_two_distinct_flags_are_candidates_never_solved(tmp_path):
    other = "CSCTF{the_answer_will_follow_after_the_light}"
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(FLAG, 'LANTERN')}\n"
                                                         f"\nct: {C.vigenere_encrypt(other, 'ORCHID')}\n"})
    r = K.solve(d, CSCTF, **BIG)
    assert r.status == "candidate" and set(r.flags) == {FLAG, other} and "several distinct flags" in r.notes


def test_a_flag_beside_another_clean_intercept_with_no_flag_is_a_candidate_not_solved(tmp_path):
    # Two intercepts, each under a different key of the same column: one reads as prose with no flag, the
    # other as prose holding a flag. Either may be the planted one, so the engine does not pick.
    planted = "the answer will follow after the light " + FLAG
    two = (f"ciphertext: {C.vigenere_encrypt(ENGLISH, 'ORCHID')}\n"
           f"\nct: {C.vigenere_encrypt(planted, 'LANTERN')}\n")
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": two})
    rep = K.sweep(d, FF, **BIG)
    assert sorted((r.key, bool(r.flags)) for r in rep.clean()) == [("LANTERN", True), ("ORCHID", False)]
    r = K.solve(d, CSCTF, **BIG)
    assert (r.status, r.flags) == ("candidate", (FLAG,))
    assert r.notes.startswith("1 other cipher text(s) also read cleanly with no flag (c.txt#")
    assert "may be a planted message" in r.notes
    assert len(r.evidence) == 2
    assert "key 'LANTERN'" in r.evidence[0].detail and FLAG.lower()[:10] in r.evidence[0].detail.lower()
    assert "key 'ORCHID'" in r.evidence[1].detail and C.letters(ENGLISH)[:20] in C.letters(r.evidence[1].detail)
    # The flagged intercept alone (the rival's line does not decrypt under any handout key) is solved.
    alone = put(tmp_path / "alone", {"keys.txt": KEYS, "c.txt": (
        f"ciphertext: {C.vigenere_encrypt(ENGLISH, 'WALRUS')}\n\nct: {C.vigenere_encrypt(planted, 'LANTERN')}\n")})
    assert [x.key for x in K.sweep(alone, FF, **BIG).clean()] == ["LANTERN"]
    one = K.solve(alone, CSCTF, **BIG)
    assert (one.status, one.flags) == ("solved", (FLAG,)) and "other cipher text" not in one.notes


def _clean(ct, key, plain, flags=()):
    return K.Reading(ct, "vigenere", key, "keys.txt:4", 0, plain, 0.9, ("secret",), tuple(flags), True)


def test_a_clean_flag_free_reading_of_the_flagged_text_itself_is_no_rival():
    # The flagged cipher text also reads cleanly with no flag under another key: that is the same intercept
    # under a wrong key, not a second intercept, so it does not hold the flag back from solved.
    holder = _clean("c.txt#1", "LANTERN", "the answer " + FLAG, [FLAG])
    same = _clean("c.txt#1", "ORCHID", ENGLISH)
    r = K.result_of(K.Report(readings=[holder, same]), FF)
    assert (r.status, r.flags) == ("solved", (FLAG,)) and "other cipher text" not in r.notes
    assert len(r.evidence) == 1 and "key 'LANTERN'" in r.evidence[0].detail
    # Beside a clean reading of a second cipher text, only that second text is the rival.
    other = _clean("c.txt#2", "TULIPS", ENGLISH)
    r = K.result_of(K.Report(readings=[holder, same, other]), FF)
    assert (r.status, r.flags) == ("candidate", (FLAG,))
    assert r.notes.startswith("1 other cipher text(s) also read cleanly with no flag (c.txt#2):")
    assert [e.detail.split(":")[0] for e in r.evidence] == ["c.txt#1", "c.txt#2"]
    assert "key 'ORCHID'" not in " ".join(e.detail for e in r.evidence)


def test_rival_readings_keep_room_in_the_evidence_beside_many_flags():
    # Eight flag-holding readings would fill the evidence on their own: the flag-free clean readings of other
    # cipher texts still get up to half of it, so the planted-versus-genuine question stays visible.
    holders = [_clean(f"c.txt#{i}", "LANTERN", FLAG, [FLAG]) for i in range(1, K.EVIDENCE_MAX + 1)]
    one = [_clean("r.txt#1", "ORCHID", ENGLISH)]
    r = K.result_of(K.Report(readings=holders + one), FF)
    assert r.status == "candidate" and len(r.evidence) == K.EVIDENCE_MAX == 8
    assert [e.detail.split(":")[0] for e in r.evidence] == [f"c.txt#{i}" for i in range(1, 8)] + ["r.txt#1"]
    rivals = [_clean(f"r.txt#{i}", "ORCHID", ENGLISH) for i in range(1, 6)]   # five rivals: capped at half
    r = K.result_of(K.Report(readings=holders + rivals), FF)
    assert [e.detail.split(":")[0] for e in r.evidence] == ([f"c.txt#{i}" for i in range(1, 5)]
                                                             + [f"r.txt#{i}" for i in range(1, 5)])


def test_prefix_case_is_normalised_to_the_profile(tmp_path):
    lower = FLAG.replace("CSCTF", "csctf")
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(lower, 'LANTERN')}\n"})
    assert K.solve(d, CSCTF, **BIG).flags == (FLAG,)


def test_without_a_profile_the_sweep_runs_and_says_flags_were_not_searched(tmp_path):
    d = put(tmp_path / "ch", {"keys.txt": KEYS, "c.txt": f"ciphertext: {C.vigenere_encrypt(FLAG, 'LANTERN')}\n"})
    r = K.solve(d, None, **BIG)
    assert r.status == "unsure" and r.flags == () and "flag format is not known" in r.notes
    assert FLAG in r.evidence[0].detail


def test_no_cipher_text_is_none_and_nothing_is_harvested_or_written(tmp_path):
    d = put(tmp_path / "ch", {"readme.txt": ENGLISH + "\n", "keys.txt": KEYS})
    rep = K.sweep(d, FF, **BIG)
    assert rep.ciphertexts == [] and rep.index_runs == [] and rep.keys == [] and rep.trials == 0
    r = K.solve(d, CSCTF, **BIG)
    assert r.status == "none" and r.notes.startswith("no keyed cipher text or book-cipher index run")
    assert not (d / "recon").exists()


def test_missing_and_empty_folders_are_blocked_with_the_reason(tmp_path):
    r = K.solve(tmp_path / "nope", CSCTF)
    assert r.status == "blocked" and "no such challenge folder" in r.notes and "nope" in r.notes
    (tmp_path / "empty").mkdir()
    r = K.solve(tmp_path / "empty", CSCTF)
    assert r.status == "blocked" and "no readable handout file under the folder itself" in r.notes


# ---------------------------------------------------------------- the budget

class Steps:
    """A clock that moves one second each time it is read."""

    def __init__(self):
        self.t = 0

    def __call__(self):
        self.t += 1
        return self.t


def test_the_best_keys_go_first_so_a_cut_sweep_still_has_the_readings(tmp_path):
    d = harbour(tmp_path / "ch")
    # One read of the clock per key per cipher text. The five stated-or-hinted keys of the rota on
    # both intercepts are ten reads; the eleventh (the first table cell) ends the sweep.
    rep = K.sweep(d, FF, budget=K.Budget(cpu=11, wall=1e9, cpu_clock=Steps()))
    tier0 = [k.text for k in rep.keys if k.tier == 0]
    assert tier0 == ["OSPREY", "HERON", "Calypso", "MARLIN", "PETREL"]
    assert [r.key for r in rep.clean()] == ["HERON", "MARLIN"]
    assert rep.cut == "11 CPU seconds" and 0 < rep.trials < rep.planned
    r = K.result_of(rep, FF)
    assert r.status == "unsure" and f"budget spent (11 CPU seconds) after {rep.trials} of {rep.planned} decrypts" in r.notes


def test_a_sweep_cut_before_anything_read_is_unsure_not_none(tmp_path):
    d = harbour(tmp_path / "ch")
    rep = K.sweep(d, FF, budget=K.Budget(cpu=2, wall=1e9, cpu_clock=Steps()))
    assert rep.clean() == [] and rep.cut == "2 CPU seconds"
    r = K.result_of(rep, FF)
    assert r.status == "unsure" and r.notes.startswith("nothing clean yet, and the sweep did not finish")


def test_a_cut_sweep_of_unmarked_text_only_is_none_not_a_lead(tmp_path):
    d = put(tmp_path / "ch", {"note.enc": C.vigenere_encrypt(ENGLISH, "WALRUS") + "\n", "keys.txt": KEYS})
    rep = K.sweep(d, FF, budget=K.Budget(cpu=2, wall=1e9, cpu_clock=Steps()))
    assert [c.kind for c in rep.ciphertexts] == ["whole"] and rep.cut and rep.clean() == []
    r = K.result_of(rep, FF)
    assert r.status == "none" and r.notes.startswith("no marked cipher text; the files and paragraphs that do not read")
    assert "budget spent (2 CPU seconds)" in r.notes


def test_an_index_run_the_budget_never_reached_is_not_called_unreadable(tmp_path):
    d = put(tmp_path / "ch", {F: song_text(F), B: song_text(B), "cipher.txt": book_indices()})
    rep = K.sweep(d, flagfmt.for_profile(PINK), budget=K.Budget(cpu=1, wall=1e9, cpu_clock=Steps()))
    assert rep.unreached == {"cipher.txt#idx1"} and rep.book == []
    r = K.result_of(rep, flagfmt.for_profile(PINK))
    assert r.status == "unsure" and r.notes.startswith("nothing clean yet, and the sweep did not finish")
    assert r.evidence == ()


def test_the_wall_budget_cuts_too_and_names_itself():
    b = K.Budget(cpu=1e9, wall=3, cpu_clock=lambda: 0.0, wall_clock=Steps())
    assert [b.over(), b.over(), b.over()] == [False, False, True]
    assert b.spent == "3 wall seconds" and b.over() and b.seconds() == 4       # no clock read once it is spent


# ---------------------------------------------------------------- where the handout is read from

def test_the_sweep_output_is_preferred_and_archive_members_give_keys(tmp_path):
    ct = C.vigenere_encrypt(PLAIN1, "HERON")
    d = put(tmp_path / "ch", {
        "files/log.txt": log(ct, "AB"), "files/handout.zip": b"PK\x03\x04 not opened here",
        "unpacked/log.txt": log(ct, "AB"), "unpacked/handout.zip": b"PK\x03\x04 not opened here",
        "unpacked/handout.zip.unpacked/rota.txt": ROTA, "unpacked/handout.zip.unpacked/orders.txt": ORDERS,
        "unpacked/.sweep.json": "{\"words\": \"SWEEPWORD\"}", "challenge.json": json.dumps({"id": 9128, "name": "Net"}),
        "notes.md": "NOTEWORD\n", "recon/index.md": "RECONWORD\n"})
    rep = K.sweep(d, FF, **BIG)
    assert rep.where == "the sweep's scratch copy" and rep.docs == 3 and rep.binaries == 1
    (r,) = rep.clean()
    assert (r.ciphertext, r.key, r.plaintext) == ("unpacked/log.txt#1", "HERON", PLAIN1)
    assert "unpacked/handout.zip.unpacked/rota.txt:7" in r.key_source
    assert not {"SWEEPWORD", "NOTEWORD", "RECONWORD"} & {k.text for k in rep.keys}
    res = K.solve(d, CSCTF, **BIG)
    assert res.challenge_id == "9128" and res.evidence[0].path == "unpacked/log.txt"


def test_files_folder_is_used_when_there_is_no_sweep_output(tmp_path):
    d = put(tmp_path / "ch", {"files/log.txt": log(C.vigenere_encrypt(PLAIN1, "HERON"), "AB"),
                              "files/rota.txt": ROTA, "files/orders.txt": ORDERS, "stray.txt": "key: WALRUS\n"})
    rep = K.sweep(d, FF, **BIG)
    assert rep.where == "files/ (no sweep output)" and rep.docs == 3
    assert "WALRUS" not in {k.text for k in rep.keys} and [r.key for r in rep.clean()] == ["HERON"]


def test_secret_and_harness_paths_are_never_read(tmp_path):
    d = put(tmp_path / "ch", {"msg.txt": "ciphertext: " + C.vigenere_encrypt(ENGLISH, "WALRUS") + "\n",
                              ".ctf/token": "key: WALRUS\n", ".env": "KEY=WALRUS\n", ".env.local": "KEY=WALRUS\n",
                              ".git/config": "key: WALRUS\n", "recon/x.txt": "key: WALRUS\n"})
    rep = K.sweep(d, FF, **BIG)
    assert rep.docs == 1 and "WALRUS" not in {k.text for k in rep.keys} and rep.clean() == []


def test_harness_names_are_skipped_only_where_the_harness_puts_them(tmp_path):
    msg = "ciphertext: " + C.vigenere_encrypt(ENGLISH, "WALRUS") + "\n"
    # The folder itself: its own notes.md, triage.md and SOLVED are the harness's; the same names deeper
    # down are handout files and are read.
    top = put(tmp_path / "top", {"msg.txt": msg, "notes.md": "key: OSPREY\n", "triage.md": "key: OSPREY\n",
                                 "SOLVED": "key: OSPREY\n", "challenge.toml": "name = 'x'\n",
                                 "handout/notes.md": "key: WALRUS\n", "handout/challenge.json": "{\"k\": \"HERONS\"}\n"})
    rep = K.sweep(top, FF, **BIG)
    assert rep.docs == 3 and "OSPREY" not in {k.text for k in rep.keys}
    assert {"WALRUS", "HERONS"} <= {k.text for k in rep.keys}
    assert [(r.key, C.letters(r.plaintext)) for r in rep.clean()] == [("WALRUS", C.letters(ENGLISH))]
    # The sweep's scratch copy: its own .sweep.json, .sweep-owner and .lock sit at its top and are skipped;
    # an archive member of one of those names (or a harness name) is read.
    scratch = put(tmp_path / "scratch", {"unpacked/msg.txt": msg, "unpacked/.lock": "key: OSPREY\n",
                                         "unpacked/.sweep-owner": "key: OSPREY\n",
                                         "unpacked/a.zip.unpacked/.lock": "key: WALRUS\n",
                                         "unpacked/a.zip.unpacked/notes.md": "key: MARLIN\n"})
    rep = K.sweep(scratch, FF, **BIG)
    assert rep.docs == 3 and "OSPREY" not in {k.text for k in rep.keys}
    assert {"WALRUS", "MARLIN"} <= {k.text for k in rep.keys} and [r.key for r in rep.clean()] == ["WALRUS"]
    # files/ holds the organisers' files only: a notes.md there is theirs.
    given = put(tmp_path / "given", {"files/msg.txt": msg, "files/notes.md": "key: WALRUS\n"})
    assert [r.key for r in K.sweep(given, FF, **BIG).clean()] == ["WALRUS"]


def test_the_brief_is_a_key_source_and_can_hold_the_cipher_text(tmp_path):
    enc = C.vigenere_encrypt(ENGLISH, "WALRUS")
    d = put(tmp_path / "a", {"files/msg.txt": f"ciphertext: {enc}\n",
                             "challenge.json": json.dumps({"id": 3, "name": "Tusk", "description": "Ask the WALRUS."})})
    (r,) = K.sweep(d, FF, **BIG).clean()
    assert (r.key, r.key_source, r.plaintext) == ("WALRUS", "brief:2 (upper-case token)", ENGLISH)
    c = put(tmp_path / "c", {"keys.txt": KEYS.replace("ORCHID", "WALRUS"), "challenge.toml": f'description = "ct: {enc}"\n'})
    rep = K.sweep(c, FF, **BIG)
    assert [x.id for x in rep.ciphertexts] == ["brief#1"] and [x.key for x in rep.clean()] == ["WALRUS"]
    assert K.result_of(rep, FF).evidence[0].path is None
    given = K.sweep(put(tmp_path / "e", {"keys.txt": KEYS.replace("ORCHID", "WALRUS")}), FF, brief=f"ct: {enc}", **BIG)
    assert [x.key for x in given.clean()] == ["WALRUS"]
    bare = K.sweep(put(tmp_path / "f", {"keys.txt": KEYS.replace("ORCHID", "WALRUS")}), FF, brief=enc, **BIG)
    assert [x.id for x in bare.ciphertexts] == ["brief#whole"]    # a brief that is nothing but the cipher text
    assert [(x.key, x.plaintext) for x in bare.clean()] == [("WALRUS", ENGLISH)]


def test_a_brief_that_does_not_parse_is_said(tmp_path):
    d = put(tmp_path / "ch", {"files/msg.txt": "ciphertext: QWERTYUIOPAS\n", "challenge.json": "{not json"})
    rep = K.sweep(d, FF, **BIG)
    assert "brief not read: challenge.json does not parse (JSONDecodeError)" in rep.notes


@pytest.mark.parametrize("data,want", [
    ("héllo wörld\n".encode("utf-8"), "héllo wörld\n"),
    (b"\xef\xbb\xbfbom\r\nline\r", "bom\nline\n"),
    ("wide ö\n".encode("utf-16"), "wide ö\n"),
    ("caf\xe9\n".encode("latin-1"), "café\n"),
    (b"\x00\x01binary", None),
    (b"text\x07bell", None),
    (b"\x93quoted\x94 cp1252", None),
    (b"\xff\xfe\x00", None),
])
def test_decode_takes_text_and_refuses_binary(data, want):
    assert K.decode(data) == want


def test_binary_tokens_are_word_like_strings_ascii_then_wide_each_once():
    data = (b"\x00\x01LANTERN\x00ab\x00x9z\x00LANTERN\xffkey-word_2\x00" + "WALRUS".encode("utf-16-le") + b"\x00\x00"
            + b"9lives " + b"A" * 41)
    # not: ab (two characters), lives (after a digit), the 41 As (too long)
    assert K.binary_tokens(data) == ["LANTERN", "x9z", "key-word_2", "WALRUS"]


def test_binary_strings_stop_at_the_total_and_at_the_budget(tmp_path, monkeypatch):
    blob = put(tmp_path / "bin", {n: b"\x00" + b"\x00".join(f"{n[0]}WORD{c}".encode() for c in "ABC") for n in ("a.bin", "b.bin", "c.bin")})
    files = [(n, blob / n) for n in ("a.bin", "b.bin", "c.bin")]
    monkeypatch.setattr(K, "BINARY_KEYS_TOTAL", 4)
    notes = []
    ks = K.harvest_keys([], binaries=files, notes=notes)
    assert len(ks) == 6 and notes == ["the strings of 1 binary file(s) (from c.bin) are not tried as keys: 4 taken already"]
    notes = []
    spent = K.Budget(cpu=1, wall=1e9, cpu_clock=Steps())
    assert spent.over()
    assert K.harvest_keys([], binaries=files, notes=notes, budget=spent) == []
    assert notes == ["the strings of 3 binary file(s) (from a.bin) are not tried as keys: the budget is spent"]


def test_caps_on_files_binary_strings_and_corpora_are_said(tmp_path, monkeypatch):
    monkeypatch.setattr(K, "MAX_FILES", 2)
    notes = []
    got, _bins, _where = K.read_handout(put(tmp_path / "many", {f"{n}.txt": "text\n" for n in "abc"}), notes)
    assert [d.rel for d in got] == ["a.txt", "b.txt"]
    assert notes == ["more than 2 handout files: the rest (from c.txt) is not read"]
    monkeypatch.setattr(K, "BINARY_KEYS", 2)
    blob = put(tmp_path / "bin", {"x.bin": b"\x00" + b"\x00".join(w.encode() for w in ("ALPHA", "BRAVO", "CHARLIE", "DELTA"))})
    notes = []
    ks = K.harvest_keys([], binaries=[("x.bin", blob / "x.bin"), ("gone.bin", blob / "gone.bin")], notes=notes)
    assert [k.text for k in ks] == ["ALPHA", "BRAVO"]
    assert notes == ["x.bin: more than 2 strings, the rest are not tried as keys",
                     "gone.bin: unreadable (FileNotFoundError), its strings are not tried as keys"]
    monkeypatch.setattr(K, "MAX_CORPORA", 1)
    notes = []
    got = K.load_corpora(docs(**{"a.txt": "word " * 40, "b.txt": "word " * 40}), [], notes)
    assert [c.name for c in got] == ["a.txt"] and notes == ["2 corpora: only the first 1 are used"]


def test_a_report_that_cannot_be_written_is_said_and_the_result_stands(tmp_path):
    d = harbour(tmp_path / "ch")
    blocker = tmp_path / "file"
    blocker.write_text("not a folder")
    r = K.solve(d, CSCTF, out=str(blocker / "out"), **BIG)
    assert r.status == "unsure" and len(r.evidence) == 2
    assert "report not written to" in r.notes and "report: " not in r.notes
    assert not (d / "recon").exists()
    ok = K.solve(d, CSCTF, out=str(tmp_path / "elsewhere"), **BIG)
    assert f"report: {tmp_path / 'elsewhere' / 'keyed_sweep.md'}" in ok.notes and (tmp_path / "elsewhere" / "keyed_sweep.json").is_file()


def test_big_files_are_corpora_only_and_huge_ones_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(K, "MAX_DOC", 200)
    monkeypatch.setattr(K, "MAX_CORPUS", 2000)
    monkeypatch.setattr(K, "MAX_BINARY", 2000)
    d = put(tmp_path / "ch", {"big.txt": "key: WALRUS\n" + "word " * 100, "huge.txt": "x" * 3000,
                              "msg.txt": "ciphertext: " + C.vigenere_encrypt(ENGLISH, "WALRUS") + "\n"})
    rep = K.sweep(d, FF, **BIG)
    assert "big.txt: over 200 characters, used as a book corpus only" in rep.notes
    assert "huge.txt: 3000 bytes, not read" in rep.notes
    assert rep.docs == 2 and "WALRUS" not in {k.text for k in rep.keys}


# ---------------------------------------------------------------- book ciphers

SONGS = {
    "night_ferry.txt": ("Night Ferry", [
        ("Verse 1", ["Pale lamps along the quay tonight", "In the fog the engines hum", "Nobody waits beside the light",
                     "Keep the rhythm, beat the drum"]),
        ("Refrain", ["We sail before the morning tide", "Every rope is cast away"]),
        ("Verse 2", ["Pink sky above the breakwater", "Sing it loud across the bay", "Humming with the diesel's roar"]),
        ("Bridge", ["Under stars the gulls are sleeping", "Somewhere east a bell is keeping time"]),
    ]),
    "harbour_bells.txt": ("Harbour Bells", [
        ("Verse 1", ["Kettles on and windows shut", "Ink still wet upon the chart", "Nets are drying in the hut"]),
        ("Refrain", ["Ring the bells along the wall", "Engines wake and seabirds call"]),
        ("Verse 2", ["Pilots wave from every boat", "Gently now the hawsers go", "Morning finds us all afloat"]),
    ]),
}


def song_text(name: str) -> str:
    title, parts = SONGS[name]
    return title + "\n\n" + "\n\n".join(f"{head}\n" + "\n".join(lines) for head, lines in parts) + "\n"


def idx(song: str, head: str, line: int, text: str) -> str:
    """`Name:Section:Line:Char` for the first place `text` starts in that line, from the fixture's own
    structure: verses by their number, other sections by their first letter."""
    name = {"night_ferry.txt": "Ferry", "harbour_bells.txt": "Bells"}[song]
    lines = dict(SONGS[song][1])[head]
    at = lines[line - 1].index(text) + 1
    label = head.split()[1] if head.startswith("Verse") else head[0]
    return f"{name}:{label}:{line}:{at}"


BOOK_FLAG = "PINK{keep_the_engines_humming}"
F, B = "night_ferry.txt", "harbour_bells.txt"


def book_indices(broken: bool = False, off: int = 0) -> str:
    """The flag's indices; broken (or off=-1) moves the i of "engines" one lower, off=+1 one higher."""
    i_of_engines = idx(F, "Verse 2", 2, "it loud")               # the i of "Sing it loud"; one lower is the blank
    off = -1 if broken else off
    if off:
        head, sec, line, at = i_of_engines.split(":")
        i_of_engines = f"{head}:{sec}:{line}:{int(at) + off}"
    parts = [idx(F, "Verse 1", 1, "P"), idx(B, "Verse 1", 2, "I"), idx(F, "Verse 1", 3, "N"), idx(B, "Verse 1", 1, "K"),
             "{",
             idx(F, "Bridge", 2, "keeping"), idx(F, "Verse 1", 2, "engines"), idx(B, "Refrain", 2, "e and"),
             idx(F, "Verse 1", 4, "p the"),
             "_",
             idx(F, "Verse 1", 2, "the"), idx(B, "Verse 2", 2, "hawsers"), idx(F, "Refrain", 1, "e sail"),
             "_",
             idx(B, "Refrain", 2, "e and"), idx(F, "Verse 1", 2, "ngines"), idx(B, "Verse 2", 2, "go"), i_of_engines,
             idx(F, "Verse 1", 2, "nes hum"), idx(F, "Verse 1", 2, "es hum"), idx(B, "Verse 1", 3, "s are"),
             "_",
             idx(F, "Verse 1", 2, "hum"), idx(F, "Verse 1", 2, "um"), idx(F, "Verse 1", 2, "m"), idx(F, "Verse 2", 3, "mming"),
             idx(F, "Verse 2", 3, "ing"), idx(F, "Verse 2", 3, "ng"), idx(F, "Verse 2", 3, "g with"),
             "}"]
    return "\n".join(parts) + "\n"


def test_index_run_keeps_names_labels_and_the_literals_between():
    (run,), spans = K.find_index_runs(docs(**{"c.txt": "The numbers:\n" + book_indices()}))
    assert (run.id, run.doc, run.line, run.arity, run.names) == ("c.txt#idx1", "c.txt", 2, 4, ("Ferry", "Bells"))
    assert len(run.tuples) == 25 and run.items[0] == ("Ferry", 1, 1, 1) and run.items[4] == "{"
    assert run.items[5] == ("Ferry", "B", 2, 26) and run.items[-1] == "}" and run.items.count("_") == 3
    assert spans == {"c.txt": set(range(1, 31))}                  # every index and literal line, not the title


@pytest.mark.parametrize("text", [
    "06:10-07:40  08:55-11:00  09:00-10:55  13:20-14:35\n",       # time ranges
    "14.08.2026 and 15.08.2026 and 16.08.2026 and 17.08.2026\n",  # dates with words between
    "1:2:3 4:5:6 7:8:9\n",                                        # three: under the minimum
    "1:2:3 4:5:6 7-8-9 1:2:3 4.5.6\n",                            # the separator changes
    "1:2:3 4:5 6:7:8 9:1\n",                                      # the arity changes
    "1 2 3 4 5 6 7\n",                                            # seven plain numbers
    "5 5 5 5 5 5 5 5 5 5\n",                                      # one number repeated
    "port 1 2 3 4 5 6 7 8 9\n",                                   # numbers on a line with words
    "preamble:8 PRN:6 type:6 TOW:17 alert:1 PRN:6\n",             # a name and one number: a field list
    "scipy1:18:1 numpy2:11:2 shapely2:2:0 scipy1:0:1 jbpy0:6:1\n",   # a different name on nearly every tuple
])
def test_what_is_not_an_index_run(text):
    assert K.find_index_runs(docs(**{"c.txt": text}))[0] == []


def test_plain_numbers_and_tuples_with_other_separators_are_runs():
    runs, spans = K.find_index_runs(docs(**{"c.txt": "3 1 4 1 5\n9 2 6 5\n\nsee 2.7.1, 8.2.8, 1.8.2, 8.4.5.\n"}))
    assert [(r.id, r.line, r.arity, r.tuples) for r in runs] == [
        ("c.txt#idx1", 1, 1, [(3,), (1,), (4,), (1,), (5,), (9,), (2,), (6,), (5,)]),
        ("c.txt#idx2", 4, 3, [(2, 7, 1), (8, 2, 8), (1, 8, 2), (8, 4, 5)])]
    assert spans == {"c.txt": {0, 1, 3}}


def test_titled_sections_and_how_an_index_names_one():
    text = song_text(F)
    secs = K.titled_sections(text)
    assert [(w, n) for w, n, _ in secs] == [("verse", 1), ("refrain", None), ("verse", 2), ("bridge", None)]
    assert secs[1][2].split("\n")[:2] == ["We sail before the morning tide", "Every rope is cast away"]
    assert K._titled(text, 2, 1).startswith("Pink sky") and K._titled(text, "R", 1).startswith("We sail")
    assert K._titled(text, "b", 1).startswith("Under stars") and K._titled(text, 3, 1) is None
    assert K._titled(text, "X", 1) is None
    plain = "Intro\nla la\n\nChorus\nna na\n\nOutro\nbye\n"          # no heading carries a number: by position
    assert (K._titled(plain, 2, 1), K._titled(plain, 2, 0), K._titled(plain, 4, 1)) == ("na na\n", "bye\n", None)
    assert K.titled_sections("A long line that is not a heading at all, clearly\ntext\n") == ()
    assert K.titled_sections("two words\nRefrain\nmore\n") == ()   # a heading needs a blank line before it
    assert K.titled_sections("Refrain\n\nmore here\n") == ()        # and text right under it


CORPUS = "One two, three.\nFour five six\n\nSeven (eight) nine\nTen eleven twelve\n"


@pytest.mark.parametrize("chain,index,base,want", [
    (("word>initial",), (4,), 1, "F"), (("word>initial",), (4,), 0, "f"), (("word",), (2,), 1, "two"),
    (("letter",), (4,), 1, "t"), (("char",), (4,), 1, " "), (("char",), (4,), 0, "t"),
    (("line", "word>initial"), (3, 2), 1, "e"), (("line", "word"), (3, 2), 1, "eight"),
    (("line", "letter"), (2, 5), 1, "f"), (("line", "char"), (2, 5), 1, " "), (("word", "letter"), (8, 2), 1, "i"),
    (("section", "word>initial"), (2, 4), 1, "T"),
    (("section", "line", "word>initial"), (2, 2, 3), 1, "t"), (("section", "line", "word"), (1, 1, 3), 1, "three"),
    (("section", "line", "letter"), (2, 1, 6), 1, "e"), (("section", "line", "char"), (2, 1, 7), 1, "("),
    (("line", "word", "letter"), (3, 2, 1), 1, "e"), (("section", "line", "word", "letter"), (2, 1, 2, 5), 1, "t"),
    (("word",), (13,), 1, None), (("line", "char"), (5, 1), 1, None), (("line", "word"), (0, 1), 1, None),
    (("section", "line", "char"), ("R", 1, 1), 1, None),
])
def test_pick_counts_in_the_units_of_the_scheme(chain, index, base, want):
    assert K.pick(CORPUS, chain, index, base) == want


def test_book_cipher_named_songs_read_as_written_is_solved(tmp_path):
    d = put(tmp_path / "ch", {F: song_text(F), B: song_text(B), "cipher.txt": book_indices()})
    rep = K.sweep(d, flagfmt.for_profile(PINK), **BIG)
    top = rep.book[0]
    assert (top.ciphertext, top.cipher, top.key, top.plaintext) == (
        "cipher.txt#idx1", "book titled/line/char base 1", "by name", BOOK_FLAG)
    assert top.clean and top.failed == 0 and top.flags == (BOOK_FLAG,) and top.key_source == f"{F}, {B}"
    assert [r for r in rep.book if r.clean] == [top]              # no other scheme reads it
    assert [c.id for c in rep.ciphertexts if c.doc == "cipher.txt"] == []    # the index lines are not a cipher text too
    r = K.solve(d, PINK, **BIG)
    assert (r.status, r.flags) == ("solved", (BOOK_FLAG,)) and r.evidence[0].path == "cipher.txt"


def test_an_index_one_off_is_surfaced_and_its_repair_goes_first(tmp_path):
    d = put(tmp_path / "ch", {F: song_text(F), B: song_text(B), "cipher.txt": book_indices(broken=True)})
    as_written = "PINK{keep_the_eng nes_humming}"
    rep = K.sweep(d, flagfmt.for_profile(PINK), **BIG)
    top = next(r for r in rep.book if r.cipher == "book titled/line/char base 1")
    assert top.plaintext == as_written and not top.clean
    fix = top.near[0]
    assert (fix["position"], fix["index"], fix["delta"], fix["from"], fix["to"]) == (15, "Ferry:2:2:5", 1, " ", "i")
    assert fix["reading"] == BOOK_FLAG and fix["clean"] is True and fix["flags"] == [BOOK_FLAG]
    r = K.solve(d, PINK, **BIG)
    assert r.status == "candidate" and r.flags[0] == BOOK_FLAG and r.flags[-1] == as_written     # the repair leads
    assert r.notes.startswith("a book reading one index off reads cleanly where the indices as written do not")
    assert "one index off gives" in r.evidence[0].detail
    md = (d / "recon" / "engines" / "common.keyed_sweep" / "keyed_sweep.md").read_text()
    assert "one off at index 15 (Ferry:2:2:5, +1): ` ` -> `i`" in md


def test_an_index_one_too_high_is_repaired_one_lower(tmp_path):
    # The i of "Sing it loud" counted one too far lands on the t: only the repair one lower reads.
    d = put(tmp_path / "ch", {F: song_text(F), B: song_text(B), "cipher.txt": book_indices(off=1)})
    rep = K.sweep(d, flagfmt.for_profile(PINK), **BIG)
    top = next(r for r in rep.book if r.cipher == "book titled/line/char base 1")
    assert top.plaintext == "PINK{keep_the_engtnes_humming}" and not top.clean
    fix = top.near[0]
    assert (fix["position"], fix["index"], fix["delta"], fix["from"], fix["to"]) == (15, "Ferry:2:2:7", -1, "t", "i")
    assert fix["reading"] == BOOK_FLAG and fix["clean"] is True and fix["flags"] == [BOOK_FLAG]
    assert K.solve(d, PINK, **BIG).flags[0] == BOOK_FLAG


def test_result_lists_at_most_two_clean_repairs_before_the_reading_as_written():
    def fix(n):
        return {"position": n, "index": "1:1", "delta": 1, "from": "x", "to": "y", "coverage": 1.0 - n / 100,
                "clean": n != 2, "flags": [f"PINK{{fix{n}}}"], "reading": f"PINK{{fix{n}}}"}
    written = K.Reading("c.txt#idx1", "book line/char base 1", "b.txt", "b.txt", 1, "PINK{wrxttqn}", 0.4,
                        flags=("PINK{wrxttqn}",), near=[fix(1), fix(2), fix(3), fix(4)])
    rep = K.Report(book=[written], index_runs=[K.IndexRun("c.txt#idx1", "c.txt", 1, 2, [(1, 1)] * 4)])
    r = K.result_of(rep, flagfmt.for_profile(PINK))
    assert (r.status, r.flags) == ("candidate", ("PINK{fix1}", "PINK{fix3}", "PINK{wrxttqn}"))   # fix2 is not clean
    written.near = [fix(2)]                                       # no clean repair: as written leads
    r = K.result_of(rep, flagfmt.for_profile(PINK))
    assert (r.status, r.flags) == ("candidate", ("PINK{wrxttqn}", "PINK{fix2}"))
    assert r.notes.startswith("a book reading one index off reads better than the indices as written")
    written.near = [fix(1), fix(2), fix(3), fix(4)]
    written.clean = True                                          # as written reads cleanly: it leads, repairs follow
    r = K.result_of(rep, flagfmt.for_profile(PINK))
    assert (r.status, r.flags) == ("candidate", ("PINK{wrxttqn}", "PINK{fix1}", "PINK{fix2}"))
    assert r.notes.startswith("a book reading one index off reads better than the indices as written")
    written.near = []
    assert K.result_of(rep, flagfmt.for_profile(PINK)).status == "solved"


def test_named_songs_that_are_not_in_the_handout_are_a_lead_and_can_be_supplied(tmp_path):
    d = put(tmp_path / "ch", {"cipher.txt": book_indices()})
    r = K.solve(d, PINK, **BIG)
    assert r.status == "unsure" and r.flags == ()
    assert r.evidence[0].detail == ("cipher.txt#idx1: 25 book-cipher indices of 4 field(s) naming Ferry, Bells, "
                                    "no corpus read them")
    assert "'Ferry' (no corpus answers to it)" in r.notes and "--opt corpus=<file>" in r.notes
    lyrics = put(tmp_path / "lyrics", {F: song_text(F), B: song_text(B)})
    again = K.solve(d, PINK, corpus=str(lyrics), **BIG)
    assert (again.status, again.flags) == ("solved", (BOOK_FLAG,))
    one = K.solve(d, PINK, corpus=[str(lyrics / F)], **BIG)      # one of the two songs: still a lead, naming the other
    assert one.status == "unsure" and "'Bells' (no corpus answers to it)" in one.notes and "'Ferry'" not in one.notes
    with pytest.raises(FileNotFoundError, match="--opt corpus"):
        K.sweep(d, flagfmt.for_profile(PINK), corpus=str(tmp_path / "missing"), **BIG)
    assert K.solve(d, PINK, corpus=str(tmp_path / "missing"), **BIG).status == "blocked"


def test_two_corpora_answering_to_one_name_is_said_not_guessed(tmp_path):
    d = put(tmp_path / "ch", {F: song_text(F), "ferry_notes.txt": song_text(F), B: song_text(B),
                              "cipher.txt": book_indices()})
    r = K.solve(d, PINK, **BIG)
    assert r.status == "unsure" and "'Ferry' (more than one corpus answers to it)" in r.notes


def test_word_numbers_read_against_a_sibling_text_and_alone_are_only_a_note(tmp_path):
    book = ("Under the old house we found a light that will answer every secret call. " * 3
            + "Hidden water moves near here and the message must follow after.\n")
    words = book.split()
    want = ["the", "secret", "message", "hidden", "under", "the", "old", "house", "near", "water"]
    numbers = " ".join(str(next(i for i, w in enumerate(words, 1) if w.strip(".").lower() == x)) for x in want)
    d = put(tmp_path / "ch", {"book.txt": book, "n.txt": numbers + "\n"})
    rep = K.sweep(d, FF, **BIG)
    top = rep.book[0]
    assert (top.cipher, top.key, top.plaintext.lower(), top.clean) == ("book word base 1", "book.txt", " ".join(want), True)
    assert K.solve(d, CSCTF, **BIG).status == "unsure"
    alone = put(tmp_path / "alone", {"n.txt": numbers + "\n"})
    r = K.solve(alone, CSCTF, **BIG)
    assert r.status == "none" and "1 run(s) of plain numbers (n.txt#idx1) could be book-cipher word numbers" in r.notes
    same = put(tmp_path / "same", {"book.txt": book + "\n" + numbers + "\n"})   # the text and its numbers in one file
    top = K.sweep(same, FF, **BIG).book[0]
    assert (top.cipher, top.key, top.plaintext.lower(), top.clean) == ("book word base 1", "book.txt", " ".join(want), True)


def test_only_a_text_of_some_length_is_a_corpus_and_given_ones_come_first(tmp_path):
    long = "word " * 40
    given = put(tmp_path / "g", {"z_given.txt": "tiny\n"})
    notes = []
    got = K.load_corpora(docs(**{"a.txt": "word " * 39, "b.txt": long}), [str(given / "z_given.txt")], notes)
    assert [(c.name, c.given) for c in got] == [("z_given.txt", True), ("b.txt", False)] and notes == []
    put(given, {"blob.bin": b"\x00\x01\x02"})
    K.load_corpora([], [str(given)], notes)
    assert notes == [f"--opt corpus: blob.bin is not text (or over {K.MAX_CORPUS} bytes), not used"]


def test_named_indices_repeat_a_few_names():
    two = "Zorb:1:2 Kvin:2:2 Zorb:1:1 Kvin:1:1\n"                 # two names over four tuples: the most allowed
    assert [r.names for r in K.find_index_runs(docs(**{"c.txt": two}))[0]] == [("Zorb", "Kvin")]
    three = "Zorb:1:2 Kvin:2:2 Zorb:1:1 Mepa:1:1\n"
    assert K.find_index_runs(docs(**{"c.txt": three}))[0] == []


def test_an_index_run_is_not_also_swept_as_a_cipher_text(tmp_path):
    run = "Zorb:1:2:3\nKvin:2:2:1\nZorb:1:1:4\nKvin:1:1:1\nZorb:2:1:1\n"
    assert K._cipherlike(run)                                     # letters enough, and no prose: but it is indices
    rep = K.sweep(put(tmp_path / "ch", {"c.txt": run}), FF, **BIG)
    assert rep.ciphertexts == [] and [(r.id, r.names) for r in rep.index_runs] == [("c.txt#idx1", ("Zorb", "Kvin"))]


def test_index_lines_are_not_harvested_for_keys(tmp_path):
    enc = C.vigenere_encrypt(ENGLISH, "LANTERN")
    d = put(tmp_path / "ch", {"cipher.txt": "Count into the songs:\n" + book_indices() + f"\nciphertext: {enc}\n",
                              "keys.txt": KEYS})
    rep = K.sweep(d, FF, **BIG)
    assert [r.key for r in rep.clean()] == ["LANTERN"] and len(rep.index_runs) == 1
    seen = {s for k in rep.keys for s in k.sources if s.startswith("cipher.txt:")}
    assert seen == {"cipher.txt:1"}                               # the title line only: no index, no cipher text


def test_first_field_as_corpus_number(tmp_path):
    a = "\n".join(["alpha line one here", "bravo line two here"] * 12) + "\n"
    b = "\n".join(["the secret message", "hidden under house", "water light answer"] * 8) + "\n"
    run = "2:1:2 2:2:1 1:1:1 2:3:3\n"                               # corpus:line:word
    d = put(tmp_path / "ch", {"a_first.txt": a, "b_second.txt": b, "c.txt": run})
    rep = K.sweep(d, FF, **BIG)
    got = {(r.cipher, r.key): r.plaintext for r in rep.book}
    assert got[("book line/word base 1", "corpus number, base 1")] == "secret hidden alpha answer"


def test_a_reading_with_too_many_indices_outside_the_text_is_dropped():
    corpus = K.Corpus("b.txt", CORPUS)
    scorer = K.Scorer()
    inside = K.IndexRun("r", "c.txt", 1, 1, [(1,), (2,), (3,), (99,)])           # one of four outside: kept, marked
    kept = {r.cipher: r for r in K.book_readings(inside, [corpus], scorer, None, [])}
    assert kept["book word base 1"].plaintext == "One two three ?" and kept["book word base 1"].failed == 1
    assert not kept["book word base 1"].clean
    outside = K.IndexRun("r", "c.txt", 1, 1, [(1,), (2,), (98,), (99,)])         # two of four: dropped
    assert K.book_readings(outside, [corpus], scorer, None, []) == []


def test_a_reading_with_an_index_outside_the_text_is_never_a_flag():
    corpus = K.Corpus("b.txt", "Cat Tree Fox apple berry cherry dune\n")
    run = K.IndexRun("r", "c.txt", 1, 1, [(1,), (2,), (3,), "{", (4,), (5,), (99,), (6,), (7,), "}"])
    got = {r.cipher: r for r in K.book_readings(run, [corpus], K.Scorer(), FF, [])}
    hole = got["book word>initial base 1"]
    assert (hole.plaintext, hole.failed, hole.flags) == ("CTF{ab?cd}", 1, ())
    whole = K.IndexRun("r", "c.txt", 1, 1, [(1,), (2,), (3,), "{", (4,), (5,), (6,), (7,), "}"])
    full = {r.cipher: r for r in K.book_readings(whole, [corpus], K.Scorer(), FF, [])}["book word>initial base 1"]
    assert (full.plaintext, full.flags) == ("CTF{abcd}", ("CTF{abcd}",))


def test_a_repair_of_a_reading_that_still_has_a_hole_is_neither_clean_nor_a_flag(tmp_path):
    lines = book_indices(broken=True).split("\n")
    assert lines[5].startswith("Ferry:B:2:")
    lines[5] = "Ferry:B:2:99"                                     # the k of "keep": outside its line
    d = put(tmp_path / "ch", {F: song_text(F), B: song_text(B), "cipher.txt": "\n".join(lines)})
    rep = K.sweep(d, flagfmt.for_profile(PINK), **BIG)
    top = next(r for r in rep.book if r.cipher == "book titled/line/char base 1")
    assert (top.plaintext, top.failed, top.flags) == ("PINK{?eep_the_eng nes_humming}", 1, ())
    fix = top.near[0]
    assert fix["reading"] == "PINK{?eep_the_engines_humming}" and fix["coverage"] >= 0.8
    assert fix["clean"] is False and fix["flags"] == []
    assert K.result_of(rep, flagfmt.for_profile(PINK)).flags == ()


# ---------------------------------------------------------------- wiring: manifest, router, intake

def test_manifest_is_a_cheap_contract_engine_with_an_intake_table():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(REPO)}["common.keyed_sweep"]
    assert m.entry_raw == "solvers.common.keyed_sweep:solve" and m.cost_class == "cheap" and m.status == "active"
    assert (m.intake.select, m.intake.run, m.intake.spawns) == ("files", "challenge", False)
    assert m.intake.timeout > K.DEFAULT_WALL                      # the engine stops itself before intake kills it
    assert E.files_matching(m.intake.match, [(Path("06_intercepts.txt"), b"x")])
    assert E.files_matching(m.intake.match, [(Path("rota.csv"), b"x")])
    assert not E.files_matching(m.intake.match, [(Path("photo.png"), b"\x89PNG")])


def test_router_sends_keyed_cipher_briefs_here():
    from ctf.engines import router

    def ids(cat, text):
        return [h.manifest.id for h in router.route(cat, text)]
    crypto = ids("crypto", "An old Vigenere message; the key is somewhere in the files.")
    assert crypto.index("common.keyed_sweep") < crypto.index("common.classical")
    assert "common.keyed_sweep" in ids("osint", "Two intercepts from the squadron net and a flight schedule.")
    assert "common.keyed_sweep" in ids("misc", "A book cipher keyed to two songs.")
    assert "common.keyed_sweep" not in ids("crypto", "an rsa modulus with a small exponent")
    assert "common.keyed_sweep" not in ids("web", "intercept the vigenere login")


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def _zip(members: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in members.items():
            z.writestr(zipfile.ZipInfo(n, date_time=(2026, 3, 3, 0, 0, 0)), d)
    return b.getvalue()


def test_intake_runs_the_sweep_on_an_osint_handout_with_the_key_table_in_an_archive(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    ct1, ct2 = C.vigenere_encrypt(PLAIN1, "HERON"), C.vigenere_encrypt(PLAIN2, "MARLIN")
    files = {"03_log.txt": log(ct1, ct2).encode(), "office.zip": _zip({"01_rota.txt": ROTA, "02_orders.txt": ORDERS})}
    ch = Challenge(id="41", name="Harbour", category="OSINT", points=270,
                   description="Where did the sealed crates go?", files=tuple(FileRef(f) for f in files))
    rep = I.intake_one("41", CSCTF, adapter=_Adapter(ch, files), workdir=tmp_path / "wd",
                       options=I.Options(net_guard="hook", record=False))
    (run,) = [r for r in rep.runs if r.engine == "common.keyed_sweep"]
    assert run.status == "ok" and run.result_status == "unsure" and run.flags == ()
    out = rep.dir / "recon" / "engines" / "common.keyed_sweep"
    saved = json.loads((out / "keyed_sweep.json").read_text())
    assert saved["handout"] == "the sweep's scratch copy"
    assert [(c["key"], c["plaintext"], c["clean"]) for c in saved["candidates"][:2]] == [
        ("HERON", PLAIN1, True), ("MARLIN", PLAIN2, True)]
    assert "office.zip.unpacked/01_rota.txt:7" in saved["candidates"][0]["key_source"]
    assert rep.result.flags == ()                                 # nothing here is a flag: the agent adjudicates


def test_intake_finds_a_flag_enciphered_with_a_key_from_a_sibling_table(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    files = {"note.txt": f"ciphertext: {C.vigenere_encrypt(FLAG, 'LANTERN')}\n".encode(), "lockers.txt": KEYS.encode()}
    ch = Challenge(id="42", name="Lockers", category="misc", points=100, description="Which locker?",
                   files=tuple(FileRef(f) for f in files))
    rep = I.intake_one("42", CSCTF, adapter=_Adapter(ch, files), workdir=tmp_path / "wd",
                       options=I.Options(net_guard="hook", record=False))
    (run,) = [r for r in rep.runs if r.engine == "common.keyed_sweep"]
    assert run.result_status == "solved" and tuple(run.flags) == (FLAG,)
    assert rep.status == "solved" and rep.result.flags == (FLAG,)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
