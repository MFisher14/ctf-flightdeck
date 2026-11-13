"""B-117: the symbol-stream grid detector (solvers/toolkits/symbol_stream.py).

Every stream is built here from a QR made with the `qrcode` library (or a known synthetic Data
Matrix); the shapes follow the 2026 PINK two-emoji file (nibble words, a delimiter word, dominant
words dark, a quiet-zone frame) without reading it."""
from __future__ import annotations

import io
import json
import random
import time

import pytest

import b117_fixtures as fx
import qr_matrix as qr
import symbol_stream as ss
from ctf import flagfmt

pytestmark = pytest.mark.needs_tool("py:qrcode", "py:PIL")

PROFILE = fx.profile()
# Every engine call below gets an explicit budget: the production defaults are wall-clock seconds,
# and this suite runs on a machine loaded far past its cores.
BUDGET = 3600.0
FF = flagfmt.for_profile(PROFILE)
FLAG = "CSCTF{nibble_grid_qr}"
BLUE, WHITE = "\U0001F7E6", "\u2b1c"

# A known synthetic 20x20 Data Matrix of CSCTF{barcode_round4} (the fixture of
# tests/test_matrix_barcodes_round4.py).
DATA_MATRIX = """10101010101010101010
10110001011110000011
10100110100010011000
11000000101110101101
10011111100101101010
10111010001101010111
11100110110010010010
10101010111101101101
11110101110110101000
10000011111110011011
10101011010100100100
10000001100111110001
10110011001111011100
10011100000100100111
11111111000001000010
11000011011010010001
11001001111010011100
10100101011100010101
10000101100001011010
11111111111111111111"""


def _framed(matrix, border=1):
    side = len(matrix) + 2 * border
    out = [[False] * side for _ in range(side)]
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            out[y + border][x + border] = cell
    return out


def nibble_stream(matrix, seed=12, *, final_delimiter=False, leading=False, one=BLUE, zero=WHITE,
                  ragged=True, newline="\r\n"):
    """The PINK shape: every module one nibble (a dark module one of 0000/0101/1010, a light one
    any other nibble but 1111), 1111 ending every row (the last one missing unless asked), the
    bits written as two emoji and broken into lines of unrelated lengths."""
    rng = random.Random(seed)
    dark = ("0000", "0101", "1010")
    light = [f"{v:04b}" for v in range(15) if f"{v:04b}" not in dark]
    rows = ["".join(rng.choice(dark) if cell else rng.choice(light) for cell in row) for row in matrix]
    if leading:
        bits = "".join("1111" + row for row in rows)
    else:
        bits = "1111".join(rows) + ("1111" if final_delimiter else "")
    symbols = [one if b == "1" else zero for b in bits]
    if not ragged:
        return "".join(symbols)
    lines, i = [], 0
    while i < len(symbols):
        n = 4 * rng.randint(7, 23)
        lines.append("".join(symbols[i:i + n]))
        i += n
    return newline.join(lines) + newline


def grid_text(matrix, dark="#", light="."):
    return "\n".join("".join(dark if cell else light for cell in row) for row in matrix) + "\n"


def _examine(text, **kw):
    return ss.examine({"stream.txt": text.encode("utf-8")}, FF, **kw)


# ---- symbols ---------------------------------------------------------------------------------------

def test_read_symbols_cuts_emoji_and_ignores_blanks():
    text = "\ufeff" + (BLUE + " " + WHITE + "\ufe0f\t" + BLUE) * 30 + "\r\n\r\n" + WHITE + "\ufe0f" + BLUE + "\n"
    stream = ss.read_symbols(text)
    assert stream.alphabet == [BLUE, WHITE + "\ufe0f"]
    assert stream.lines == [[0, 1, 0] * 30, [1, 0]]
    assert stream.flat == [0, 1, 0] * 30 + [1, 0]
    # a zero-width joiner sequence is one symbol, not three
    family = "\U0001F468\u200d\U0001F469"
    joined = ss.read_symbols((family + "x") * 40)
    assert joined.alphabet == [family, "x"] and joined.flat == [0, 1] * 40
    # ... and so are a skin tone on a hand and an accent on a letter
    toned, accented = "\U0001F44D\U0001F3FD", "é"
    marked = ss.read_symbols((toned + accented) * 40)
    assert marked.alphabet == [toned, accented] and marked.flat == [0, 1] * 40
    # a blank is never glued to: a mark after a space starts its own symbol
    assert ss.read_symbols(("a ́b") * 40).alphabet == ["a", "́", "b"]


def test_read_symbols_refuses_what_is_not_a_stream():
    assert ss.read_symbols("the quick brown fox jumps over the lazy dog " * 20) is None      # prose
    assert ss.read_symbols("".join(chr(0x4E00 + i) for i in range(17)) * 10) is None           # 17 symbols
    assert ss.read_symbols("".join(chr(0x4E00 + i) for i in range(16)) * 10) is not None       # 16 symbols
    assert ss.read_symbols("a" * 200) is None                                                  # one symbol
    assert ss.read_symbols("ab" * 31 + "a") is None                                            # 63 symbols
    assert ss.read_symbols("ab" * 32) is not None                                              # 64 symbols
    assert ss.read_symbols("") is None


def test_read_symbols_refuses_a_text_longer_than_any_grid(monkeypatch):
    monkeypatch.setattr(ss, "MAX_STREAM", 25)
    assert ss.read_symbols("ab" * 50) is not None                    # 100 characters: at the limit
    assert ss.read_symbols("ab" * 50 + "a") is None


def test_read_symbols_takes_one_glyph_against_spaces_as_a_drawing():
    text = "\n\n" + "\n".join(["# # # # #", " # # # #", "#########", "", "##"] * 4) + "\n   \n"
    stream = ss.read_symbols(text)
    assert stream.alphabet == ["#", " "]
    assert len(stream.lines) == 20 and {len(line) for line in stream.lines} == {9}
    assert stream.lines[0] == [0, 1, 0, 1, 0, 1, 0, 1, 0]
    assert stream.lines[1] == [1, 0, 1, 0, 1, 0, 1, 0, 1]          # padded on the right
    assert stream.lines[3] == [1] * 9                               # a blank line inside is a light row
    assert stream.lines[4] == [0, 0] + [1] * 7
    # two glyphs: the spaces only separate
    assert ss.read_symbols("# . # .\n" * 20).lines[0] == [0, 1, 0, 1]


# ---- layouts ---------------------------------------------------------------------------------------

def _stream(lines, alphabet=("a", "b")):
    return ss.Stream([list(line) for line in lines], list(alphabet))


def test_layout_lines_and_square():
    rows = [[(x * y) % 2 for x in range(10)] for y in range(9)]
    found = ss.layouts(_stream(rows))
    assert [(lay.kind, lay.word_size, len(lay.rows), len(lay.rows[0])) for lay in found] == [("lines", 1, 9, 10)]
    assert found[0].rows[3][3] == (1,)
    # nine equal lines of nine symbols are the same grid as the square: listed once, as lines
    square = [[(x + y) % 2 for x in range(9)] for y in range(9)]
    assert [(lay.kind, len(lay.rows)) for lay in ss.layouts(_stream(square))] == [("lines", 9)]
    # the same 81 symbols on ragged lines are only a square
    flat = [s for row in square for s in row]
    ragged = [flat[:50], flat[50:]]
    assert [(lay.kind, len(lay.rows), len(lay.rows[0])) for lay in ss.layouts(_stream(ragged))] == [("square", 9, 9)]
    # two-symbol words: sixteen lines of sixteen symbols are also eight-by-eight pairs
    wide = [[(x // 2 + y) % 2 for x in range(16)] for y in range(16)]
    kinds = {(lay.kind, lay.word_size, len(lay.rows), len(lay.rows[0])) for lay in ss.layouts(_stream(wide))}
    assert ("lines", 1, 16, 16) in kinds and ("lines", 2, 16, 8) in kinds


def test_layout_needs_a_real_grid():
    assert ss.layouts(_stream([[0, 1] * 4] * 7)) == []                    # seven rows
    assert ss.layouts(_stream([[0, 1, 0, 1, 0, 1, 0]] * 9)) == []         # seven columns
    assert ss.layouts(_stream([[0] * 8 + [1]] + [[0] * 9] * 7)) != []     # two distinct words is enough
    assert ss.layouts(_stream([[0] * 9] * 8)) == []                       # one distinct word is not


def _delimited_stream(rows, delimiter=2, *, leading=False, final=True, alphabet=("a", "b", "|")):
    flat = []
    for i, row in enumerate(rows):
        if leading:
            flat += [delimiter] + list(row)
        else:
            flat += list(row) + ([delimiter] if final or i < len(rows) - 1 else [])
    return ss.Stream([flat[:13], flat[13:]], list(alphabet))


def test_layout_delimiter_word_at_row_end_row_start_and_missing_at_the_end():
    rows = [[(x + 2 * y) % 2 for x in range(11)] for y in range(9)]
    for kw in ({}, {"final": False}, {"leading": True}):
        found = [lay for lay in ss.layouts(_delimited_stream(rows, **kw)) if lay.kind == "delimiter"]
        assert len(found) == 1, kw
        assert found[0].delimiter == (2,) and found[0].word_size == 1
        assert [[word[0] for word in row] for row in found[0].rows] == rows, kw


def test_layout_delimiter_must_be_regular():
    rows = [[(x + 2 * y) % 2 for x in range(11)] for y in range(9)]
    good = _delimited_stream(rows)
    flat = good.flat
    # one delimiter moved one place: not a delimiter any more
    at = flat.index(2)
    moved = flat[:at - 1] + [2, flat[at - 1]] + flat[at + 1:]
    assert not [lay for lay in ss.layouts(ss.Stream([moved], good.alphabet)) if lay.kind == "delimiter"]
    # ... also when it is one in the middle, with the first two and the ends where they belong
    at = [i for i, s in enumerate(flat) if s == 2][4]
    middle = flat[:at - 1] + [2, flat[at - 1]] + flat[at + 1:]
    assert not [lay for lay in ss.layouts(ss.Stream([middle], good.alphabet)) if lay.kind == "delimiter"]
    # a stray extra occurrence in a row
    stray = list(flat)
    stray[3] = 2
    assert not [lay for lay in ss.layouts(ss.Stream([stray], good.alphabet)) if lay.kind == "delimiter"]
    # a partial row at the end
    assert not [lay for lay in ss.layouts(ss.Stream([flat + [0, 1, 0]], good.alphabet)) if lay.kind == "delimiter"]
    # rows of seven words are too narrow, rows of eight are not
    narrow = _delimited_stream([[(x + y) % 2 for x in range(7)] for y in range(12)])
    assert not [lay for lay in ss.layouts(narrow) if lay.kind == "delimiter"]
    wide = _delimited_stream([[(x + y) % 2 for x in range(8)] for y in range(12)])
    assert [len(lay.rows[0]) for lay in ss.layouts(wide) if lay.kind == "delimiter"] == [8]
    # seven delimiters make eight rows only when the last row has no terminator
    eight = [[(x + y) % 2 for x in range(9)] for y in range(8)]
    assert [len(lay.rows) for lay in ss.layouts(_delimited_stream(eight, final=False)) if lay.kind == "delimiter"] == [8]
    seven = [[(x + y) % 2 for x in range(9)] for y in range(7)]
    assert not [lay for lay in ss.layouts(_delimited_stream(seven, final=False)) if lay.kind == "delimiter"]


# ---- words to modules ------------------------------------------------------------------------------

def test_mappings_two_words_and_most_common_splits():
    two = ss.Layout("lines", 1, None, [[(0,), (1,), (0,)], [(0,), (0,), (1,)]])
    assert ss.mappings(two, ["a", "b"]) == [("a dark", [[True, False, True], [True, True, False]])]

    # counts: x 10, y 9, z 3, w 1 -> the widest gap is after two words, then after three, then one
    words = [(0,)] * 10 + [(1,)] * 9 + [(2,)] * 3 + [(3,)]
    layout = ss.Layout("lines", 1, None, [words])
    got = ss.mappings(layout, ["x", "y", "z", "w"])
    assert [label for label, _m in got] == ["the 2 most common words dark (x y)",
                                            "the 3 most common words dark (x y z)",
                                            "the 1 most common words dark (x)"]
    assert got[0][1] == [[True] * 19 + [False] * 4]
    assert got[2][1] == [[True] * 10 + [False] * 13]


def test_mappings_symbol_positions_for_two_symbol_words(monkeypatch):
    layout = ss.Layout("lines", 2, None, [[(0, 0), (0, 1), (1, 0), (1, 1), (0, 0)]])
    got = dict(ss.mappings(layout, ["a", "b"]))
    assert got["symbol 1 of each word, b dark"] == [[False, False, True, True, False]]
    assert got["symbol 2 of each word, b dark"] == [[False, True, False, True, False]]
    assert got["the 1 most common words dark (aa)"] == [[True, False, False, False, True]]
    # a stream of more than two symbols has no bit positions to offer
    multi = ss.Layout("lines", 1, None, [[(0,), (1,), (2,), (0,)]])
    assert all(not label.startswith("symbol ") for label, _m in ss.mappings(multi, ["a", "b", "c"]))
    monkeypatch.setattr(ss, "MAX_DOMINANT", 1)
    assert len([1 for label, _m in ss.mappings(layout, ["a", "b"]) if "most common" in label]) == 1


def test_trim_border_cuts_only_uniform_edges():
    inner = [[True, False, True], [False, True, True], [True, True, False]]
    framed = [[False] * 6] + [[False] + row + [False, False] for row in inner] + [[False] * 6] * 2
    cut, border = ss.trim_border(framed)
    assert cut == inner and border == (1, 2, 1, 2)
    assert ss.trim_border(inner) == (inner, (0, 0, 0, 0))
    dark_frame = [[True] * 5] + [[True] + row + [True] for row in inner] + [[True] * 5]
    assert ss.trim_border(dark_frame) == (inner, (1, 1, 1, 1))
    assert ss.trim_border([[True, True], [True, True]])[0] == [[True]]            # never cut to nothing


# ---- the PINK shape, end to end --------------------------------------------------------------------

@pytest.mark.parametrize("kw", [{}, {"final_delimiter": True}, {"leading": True}, {"ragged": False},
                                {"one": WHITE, "zero": BLUE}, {"newline": "\n"}, {"seed": 99}],
                         ids=["as-played", "final-delimiter", "leading-delimiter", "one-line", "swapped",
                              "lf", "other-seed"])
def test_nibble_stream_with_delimiter_dominant_words_and_frame_reads(kw):
    text = nibble_stream(_framed(fx.qr_modules(FLAG, 3)), **kw)
    rep = _examine(text)
    assert len(rep.findings) == 1
    finding = rep.findings[0]
    assert finding.flags == [FLAG] and finding.symbols == len(text.replace("\r", "").replace("\n", ""))
    best = finding.read
    assert best is finding.candidates[0]
    assert (best.layout.kind, best.layout.word_size) == ("delimiter", 4)
    one = 0 if text.startswith(kw.get("one", BLUE)) else 1
    assert best.layout.delimiter == (one,) * 4
    assert (len(best.layout.rows), len(best.layout.rows[0])) == (31, 31)
    assert best.border == (1, 1, 1, 1) and best.shape == "29x29"
    assert best.mapping.startswith("the 3 most common words dark")
    reading = best.readings[0]
    assert reading["text"] == FLAG and reading["version"] == 3 and reading["repaired"] is False
    res = ss.result_of(rep)
    assert res.status == "solved" and res.flags == (FLAG,) and res.engine == "toolkits.symbol_stream"
    assert "rows ended by the word" in res.evidence[0].detail and res.evidence[0].path == "stream.txt"
    assert "border cut 1/1/1/1" in res.evidence[0].detail


def test_solve_reads_the_stream_and_writes_an_upright_matrix(tmp_path):
    turned = fx.rotate(fx.qr_modules(FLAG, 3))
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "theater.dat").write_text(nibble_stream(_framed(turned)), encoding="utf-8")
    (tmp_path / "files" / "readme.txt").write_text("The answer is in the squares. " * 30, encoding="utf-8")
    (tmp_path / "files" / "blob.bin").write_bytes(bytes(range(256)) * 8)
    res = ss.solve(tmp_path, PROFILE, seconds=BUDGET)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].path == "files/theater.dat"
    written = [e.path for e in res.evidence if e.detail == "matrix written"]
    assert written == ["recon/symbol_stream/files_theater.dat.delimiter-w4-29x29.0.png"]
    # the written picture is upright although the stream was a rotated code: it shows exactly the
    # unrotated modules, eight pixels a module inside a four-module quiet zone
    drawn = fx.png_modules((tmp_path / written[0]).read_bytes())
    assert drawn == fx.qr_modules(FLAG, 3) and drawn != turned
    seen = qr.decode_matrix(drawn)
    assert seen[0]["text"] == FLAG and seen[0]["transform"] == fx.IDENTITY
    out = tmp_path / "elsewhere"
    assert ss.solve(tmp_path, PROFILE, seconds=BUDGET, out=str(out)).status == "solved"
    assert [p.name for p in out.iterdir()] == ["files_theater.dat.delimiter-w4-29x29.0.png"]
    with pytest.raises(FileNotFoundError):
        ss.solve(tmp_path / "missing", PROFILE, seconds=BUDGET)


def test_plain_grids_lines_square_and_many_symbols():
    matrix = fx.qr_modules(FLAG, 3)
    as_lines = _examine(grid_text(matrix))
    assert as_lines.findings[0].flags == [FLAG] and as_lines.findings[0].read.layout.kind == "lines"
    flat = "".join("1" if cell else "0" for row in matrix for cell in row)
    as_square = _examine(flat[:400] + "\n" + flat[400:] + "\n")
    assert as_square.findings[0].flags == [FLAG] and as_square.findings[0].read.layout.kind == "square"
    # four symbols: two dark, one light, one ending each row
    rng = random.Random(3)
    rows = ["".join(rng.choice("AB") if cell else "C" for cell in row) + "D" for row in matrix]
    joined = "".join(rows)
    many = _examine("\n".join(joined[i:i + 37] for i in range(0, len(joined), 37)))
    best = many.findings[0].read
    assert many.findings[0].flags == [FLAG]
    assert (best.layout.kind, best.layout.word_size, best.layout.delimiter) == ("delimiter", 1, (3,))
    assert many.findings[0].alphabet == sorted(many.findings[0].alphabet, key=joined.index)


def test_finderless_code_in_a_stream_is_repaired_and_written_with_finders(tmp_path):
    gone = fx.blank_finders(fx.qr_modules(FLAG, 3))
    rep = _examine(grid_text(gone, BLUE, WHITE), out_dir=tmp_path)
    finding = rep.findings[0]
    assert finding.flags == [FLAG]
    assert finding.read.readings[0]["repaired"] is True
    res = ss.result_of(rep)
    assert res.status == "solved" and "repair decode" in res.evidence[0].detail
    assert len(rep.written) == 1
    # the picture has its finders back: it is the code as it was before they were removed, and
    # the strict decode (finder gate on) reads it
    assert qr.decode_matrix(gone) == []
    drawn = fx.png_modules(rep.written[0].read_bytes())
    assert drawn == fx.qr_modules(FLAG, 3)
    strict = qr.decode_matrix(drawn)
    assert strict[0]["text"] == FLAG and strict[0]["finder_score"] == 100 and strict[0]["repaired"] is False


def test_data_matrix_in_a_stream_goes_to_the_other_decoders():
    text = "\n".join(line.replace("1", BLUE).replace("0", WHITE) for line in DATA_MATRIX.splitlines())
    rep = _examine(text)
    finding = rep.findings[0]
    assert finding.flags == ["CSCTF{barcode_round4}"]
    assert finding.read.readings[0]["symbology"] == "datamatrix" and finding.read.shape == "20x20"
    res = ss.result_of(rep)
    assert res.status == "solved" and "datamatrix from the symbol stream" in res.evidence[0].detail


# ---- what is not solved ----------------------------------------------------------------------------

def test_payload_without_a_flag_is_unsure_and_named():
    rep = _examine(grid_text(fx.qr_modules("next stage: /vault/door-7", 3)))
    res = ss.result_of(rep)
    assert res.status == "unsure" and res.flags == ()
    assert "next stage: /vault/door-7" in res.notes and "no flag" in res.notes
    assert any(e.kind == "decode" for e in res.evidence)


def test_two_flags_in_two_files_are_candidates():
    files = {"a.txt": grid_text(fx.qr_modules("CSCTF{first_one}", 3)).encode(),
             "b.txt": grid_text(fx.qr_modules("CSCTF{second_one}", 3)).encode()}
    res = ss.result_of(ss.examine(files, FF))
    assert res.status == "candidate" and res.flags == ("CSCTF{first_one}", "CSCTF{second_one}")


def test_unread_grid_is_unsure_with_the_best_grids_written(tmp_path):
    rng = random.Random(41)
    noise = [[rng.random() < 0.5 for _ in range(29)] for _ in range(29)]
    rep = _examine(nibble_stream(_framed(noise)), out_dir=tmp_path)
    finding = rep.findings[0]
    assert finding.read is None and finding.flags == [] and len(finding.candidates) > ss.MAX_WRITTEN
    assert len(rep.written) == ss.MAX_WRITTEN and all(p.is_file() for p in rep.written)
    res = ss.result_of(rep, root=tmp_path)
    assert res.status == "unsure" and "none read by a matrix decoder" in res.notes
    assert "rows ended by the word" in res.notes                  # the delimiter layout is the one named
    assert [e.path for e in res.evidence] == [p.name for p in rep.written]
    assert all(".delimiter-w4-" in p.name for p in rep.written)
    ranks = [ss._rank(c) for c in finding.candidates]
    assert ranks == sorted(ranks, reverse=True)
    assert ss.worth_a_look(finding.candidates[0], finding.alphabet)


def test_rank_and_worth_a_look():
    def cand(kind, size, structure=None):
        return ss.Candidate(ss.Layout(kind, size, None, [[(0,)]]), "m", [[True]], (0, 0, 0, 0), structure)

    shown = {"plausible": True, "finder_score": 40, "timing_score": 100}
    faint = {"plausible": False, "finder_score": 60, "timing_score": 70}
    fainter = {"plausible": False, "finder_score": 30, "timing_score": 50}
    order = [cand("lines", 1, shown), cand("delimiter", 4), cand("square", 1, faint),
             cand("lines", 1, fainter), cand("delimiter", 1), cand("lines", 2)]
    assert sorted(reversed(order), key=ss._rank, reverse=True)[:4] == order[:4]
    two, three = ["a", "b"], ["a", "b", "c"]
    assert [ss.worth_a_look(c, two) for c in order] == [True, True, False, False, False, False]
    # the delimiter signature belongs to two-symbol streams; structure counts for any
    assert [ss.worth_a_look(c, three) for c in order] == [True, False, False, False, False, False]


def test_damaged_code_that_no_decoder_reads_is_still_reported_for_its_structure(tmp_path):
    matrix = fx.qr_modules(FLAG, 3)
    functions = qr._function_modules(3)
    rng = random.Random(77)
    broken = [[(not cell) if not functions[y][x] and rng.random() < 0.4 else cell
               for x, cell in enumerate(row)] for y, row in enumerate(matrix)]
    assert qr.decode_matrix(broken, repair=True) == []
    # three kinds of symbol, so no two-symbol signature: only the QR structure makes it reportable
    rows = ["".join(rng.choice("AB") if cell else "C" for cell in row) for row in broken]
    rep = ss.examine({"three.txt": "\n".join(rows).encode()}, FF, out_dir=tmp_path)
    finding = rep.findings[0]
    assert finding.read is None and finding.candidates[0].structure["plausible"] is True
    assert finding.candidates[0].structure["finder_score"] == 100
    assert len(rep.written) == 1                                   # only the grid with the structure
    res = ss.result_of(rep, root=tmp_path)
    assert res.status == "unsure" and "3 kinds" in res.notes


def test_few_symbol_texts_that_only_happen_to_lay_out_are_not_reported(tmp_path):
    rng = random.Random(6)
    files = {
        # a repeated sentence: twelve letters, and "T" comes once a period like a delimiter
        "prose.txt": ("The answer is in the squares. " * 30).encode(),
        # a hex dump in fixed-width lines
        "dump.hex": "\n".join("".join(rng.choice("0123456789abcdef") for _ in range(32)) for _ in range(20)).encode(),
        # bits in fixed-width lines, with no code in them
        "bits.txt": "\n".join("".join(rng.choice("01") for _ in range(24)) for _ in range(24)).encode(),
    }
    for name, data in files.items():
        stream = ss.read_symbols(data.decode())
        assert stream is not None and ss.analyse(stream), name      # each does lay out as some grid
    rep = ss.examine(files, FF, out_dir=tmp_path)
    assert rep.findings == [] and rep.written == [] and list(tmp_path.iterdir()) == []
    assert ss.result_of(rep).status == "none"


def test_files_that_are_not_streams_give_none():
    files = {"prose.txt": b"Nothing to see in this file, move along. " * 40,
             "binary.bin": bytes(range(256)) * 4,
             "utf16.txt": ("ab" * 40).encode("utf-16"),          # a stream, but with no grid in it
             "bad.txt": b"\xff\xfe\xfd" * 100}
    rep = ss.examine(files, FF)
    assert rep.findings == []
    res = ss.result_of(rep)
    assert res.status == "none" and res.flags == () and res.evidence == ()


def test_decode_text_reads_utf8_and_marked_utf16_only():
    assert ss.decode_text("ab\u2b1c".encode("utf-8")) == "ab\u2b1c"
    assert ss.decode_text("ab\u2b1c".encode("utf-16")) == "ab\u2b1c"
    assert ss.decode_text(b"a\x00b\x00") is None                 # unmarked UTF-16 is binary to us
    assert ss.decode_text(b"\xff\xfe\x00") is None               # a BOM and half a character
    assert ss.decode_text(b"\xc3\x28") is None
    grid = grid_text(fx.qr_modules(FLAG, 3)).encode("utf-16")
    assert ss.examine({"g.txt": grid}, FF).findings[0].flags == [FLAG]


def test_oversized_file_is_not_read(tmp_path, monkeypatch):
    (tmp_path / "grid.txt").write_text(grid_text(fx.qr_modules(FLAG, 3)), encoding="utf-8")
    monkeypatch.setattr(ss, "MAX_INPUT", 100)
    res = ss.solve(tmp_path, PROFILE, seconds=BUDGET)
    assert res.status == "none" and "over the 100 byte cap" in res.notes
    assert ss.examine({"grid.txt": (tmp_path / "grid.txt").read_bytes()}, FF).findings == []


# ---- budgets ---------------------------------------------------------------------------------------

def test_deadline_and_candidate_cap_stop_the_search_and_say_so(monkeypatch):
    text = nibble_stream(_framed(fx.qr_modules(FLAG, 3)))
    stream = ss.read_symbols(text)
    skipped = []
    assert ss.analyse(stream, deadline=time.monotonic() - 1, skipped=skipped) == []
    assert skipped == ["symbol stream: out of time; later layouts were not read"]
    # the winning split is the first mapping of the delimiter layout: a cap of one matrix still
    # reads it only if nothing else came first, so count what a tight cap reads instead
    reads = []
    real = ss.read_matrix

    def spy(matrix):
        reads.append(len(matrix))
        return [], None

    monkeypatch.setattr(ss, "read_matrix", spy)
    monkeypatch.setattr(ss, "MAX_CANDIDATES", 3)
    skipped = []
    got = ss.analyse(stream, skipped=skipped)
    assert len(reads) == 3 and len(got) == 3
    assert skipped == ["symbol stream: 3 matrices read; later layouts were not read"]
    monkeypatch.setattr(ss, "read_matrix", real)
    monkeypatch.setattr(ss, "MAX_CANDIDATES", 96)
    assert ss.analyse(stream)[0].readings[0]["text"] == FLAG


def test_first_reading_ends_the_search(monkeypatch):
    stream = ss.read_symbols(nibble_stream(_framed(fx.qr_modules(FLAG, 3))))
    calls = []
    real = ss.read_matrix

    def spy(matrix):
        calls.append(1)
        return real(matrix)

    monkeypatch.setattr(ss, "read_matrix", spy)
    got = ss.analyse(stream)
    assert got[0].readings and all(not c.readings for c in got[1:])
    assert len(calls) == len(got)                   # nothing was read after the one that decoded


def test_read_matrix_strict_other_then_repair(monkeypatch):
    clean = fx.qr_modules(FLAG, 3)
    order = []
    real_decode, real_other = qr.decode_matrix, qr.recognize_other
    monkeypatch.setattr(qr, "decode_matrix", lambda m, **kw: (order.append(("qr", kw.get("repair", False))), real_decode(m, **kw))[1])
    monkeypatch.setattr(qr, "recognize_other", lambda m: (order.append(("other", None)), real_other(m))[1])
    readings, structure = ss.read_matrix(clean)
    assert readings[0]["text"] == FLAG and structure is None and order == [("qr", False)]
    order.clear()
    readings, structure = ss.read_matrix(fx.blank_finders(clean))
    assert readings[0]["repaired"] is True and structure["timing_score"] == 100
    assert order == [("qr", False), ("other", None), ("qr", True)]
    order.clear()
    rng = random.Random(8)
    noise = [[rng.random() < 0.5 for _ in range(29)] for _ in range(29)]
    readings, structure = ss.read_matrix(noise)
    assert readings == [] and structure is not None
    assert order == [("qr", False), ("other", None)]              # not plausible: no repair spent on it
    order.clear()
    assert ss.read_matrix([[True, False] * 15] * 12) == ([], None)   # 12x30: no QR path at all
    assert order == [("other", None)]


# ---- CLI -------------------------------------------------------------------------------------------

def test_cli_prints_the_grid_the_reading_and_the_result(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    path = tmp_path / "theater.txt"
    path.write_text(nibble_stream(_framed(fx.qr_modules(FLAG, 3))), encoding="utf-8")
    assert ss.main([str(path), "--out", str(tmp_path / "out"), "--seconds", "3600"]) == 0
    out = capsys.readouterr().out
    assert "rows ended by the word" in out and repr(FLAG) in out
    result = json.loads(out.strip().splitlines()[-1])
    assert result["status"] == "solved" and result["flags"] == [FLAG]
    assert (tmp_path / "out").is_dir() and len(list((tmp_path / "out").iterdir())) == 1
    assert ss.main([str(tmp_path / "absent.txt")]) == 2
    assert "no such file" in capsys.readouterr().err


# ---- round 1 of verification -----------------------------------------------------------------------

def test_square_layout_needs_whole_words():
    """128 symbols are 64 two-symbol words, an 8 by 8 square. 129 are 64 words and a symbol left
    over: not a square of words, though the word count alone would say so."""
    rng = random.Random(3)
    symbols = "".join(rng.choice("ab") for _ in range(129))
    whole = [lay for lay in ss.layouts(ss.read_symbols(symbols[:128])) if lay.kind == "square"]
    assert [(lay.word_size, len(lay.rows), len(lay.rows[0])) for lay in whole] == [(2, 8, 8)]
    assert [lay for lay in ss.layouts(ss.read_symbols(symbols)) if lay.kind == "square"] == []


def test_a_matrix_is_not_read_again_as_its_own_inverse(monkeypatch):
    """Every decoder reads a matrix in both polarities, so the inverse of a matrix already read is
    the same reading again. Two-symbol words offer exactly that: 'the commoner word dark' and
    'symbol 1 of each word' are inverses."""
    rng = random.Random(4)
    text = "\n".join("".join(rng.choice(("ab", "ba")) for _ in range(8)) for _ in range(8))
    stream = ss.read_symbols(text)
    words = next(lay for lay in ss.layouts(stream) if lay.kind == "lines" and lay.word_size == 2)
    offered = [matrix for _label, matrix in ss.mappings(words, stream.alphabet)]
    assert [[not cell for cell in row] for row in offered[0]] in offered     # the layout does offer both
    read = []

    def spy(matrix):
        read.append(tuple(tuple(row) for row in matrix))
        return [], None

    monkeypatch.setattr(ss, "read_matrix", spy)
    ss.analyse(stream)
    assert read and len(read) == len(set(read))
    inverses = {tuple(tuple(not cell for cell in row) for row in matrix) for matrix in read}
    assert not inverses & set(read)
