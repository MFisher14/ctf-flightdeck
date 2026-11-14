"""B-117: QR probe and repair in solvers/toolkits/qr_matrix.py.

A QR whose finder patterns were removed or whose format string is destroyed still reads, because
Reed--Solomon plus an exactly parsing payload stays the acceptance boundary. Every matrix is built
here with the `qrcode` library; nothing external is read."""
from __future__ import annotations

import io
import json
import random
import time

import pytest

import b117_fixtures as fx
import qr_matrix as qr

pytestmark = pytest.mark.needs_tool("py:qrcode", "py:PIL")

FLAG = "CSCTF{finders_gone}"


def _texts(results):
    return [item["text"] for item in results]


# ---- decode_matrix(repair=True) ---------------------------------------------------------------------

@pytest.mark.parametrize("version", [1, 3, 7, 18])
def test_removed_finders_read_only_with_repair(version):
    payload = "CSCTF{v%d}" % version
    gone = fx.blank_finders(fx.qr_modules(payload, version))
    assert qr._finder_score(gone) < qr.FINDER_GATE
    assert qr.decode_matrix(gone) == []
    found = qr.decode_matrix(gone, repair=True)
    assert _texts(found) == [payload]
    assert found[0]["repaired"] is True and found[0]["version"] == version
    assert found[0]["transform"] == fx.IDENTITY


def test_dark_painted_and_inverted_finders_read_with_repair():
    clean = fx.qr_modules(FLAG, 4, "H")
    painted = fx.blank_finders(clean, value=True)
    assert qr.decode_matrix(painted) == []
    assert _texts(qr.decode_matrix(painted, repair=True)) == [FLAG]
    flipped = [row[:] for row in clean]
    for cx, cy in ((3, 3), (len(clean) - 4, 3), (3, len(clean) - 4)):
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                flipped[cy + dy][cx + dx] = not flipped[cy + dy][cx + dx]
    assert qr.decode_matrix(flipped) == []
    assert _texts(qr.decode_matrix(flipped, repair=True)) == [FLAG]


def test_clean_symbol_is_not_called_repaired_either_way():
    clean = fx.qr_modules(FLAG, 4, "H")
    strict = qr.decode_matrix(clean)
    assert _texts(strict) == [FLAG] and strict[0]["repaired"] is False
    forced = qr.decode_matrix(clean, repair=True)
    assert _texts(forced) == [FLAG] and forced[0]["repaired"] is False
    assert forced[0]["format_distance"] == 0 and forced[0]["mask"] == strict[0]["mask"]


def test_repair_tries_the_likeliest_orientation_first_and_stops_at_a_reading(monkeypatch):
    turned = fx.invert(fx.rotate(fx.rotate(fx.blank_finders(fx.qr_modules(FLAG, 4, "H")))))
    reads = []
    real = qr._extract
    monkeypatch.setattr(qr, "_extract", lambda m, version, mask: (reads.append(mask), real(m, version, mask))[1])
    found = qr.decode_matrix(turned, repair=True)
    assert _texts(found) == [FLAG]
    # the timing lines and the format string single out the orientation, and its format code is
    # intact: one unmasking, not the 512 a blind sweep of 16 orientations and 32 formats could take
    assert reads == [found[0]["mask"]]
    # with the format string destroyed too, every format is forced, but still in one orientation
    reads.clear()
    wrecked = fx.invert(fx.rotate(fx.wreck_format(fx.blank_finders(fx.qr_modules(FLAG, 4, "H")))))
    assert _texts(qr.decode_matrix(wrecked, repair=True)) == [FLAG]
    assert 1 <= len(reads) <= 32


def test_destroyed_format_string_is_reported_as_repaired():
    wrecked = fx.wreck_format(fx.qr_modules(FLAG, 4, "H"))
    assert min(distance for distance, _e, _m in qr._format_candidates(wrecked)) > 3
    found = qr.decode_matrix(wrecked)
    assert _texts(found) == [FLAG]
    assert found[0]["repaired"] is True and found[0]["format_distance"] > 3


def test_finders_and_format_both_gone_in_an_unknown_orientation():
    upright = fx.wreck_format(fx.blank_finders(fx.qr_modules(FLAG, 5, "Q")))
    turned = fx.invert(fx.rotate(fx.transpose(upright)))
    assert qr.decode_matrix(turned) == []
    found = qr.decode_matrix(turned, repair=True)
    assert _texts(found) == [FLAG] and len(found) == 1
    assert found[0]["transform"] != fx.IDENTITY
    # The reported transform really is the way back to an upright symbol: oriented and with the
    # fixed patterns painted in, the strict path reads it with no transform at all. (The format
    # string is still destroyed, so the strict read forces the format and says so.)
    restored = qr.restore_finders(qr.apply_transform(turned, found[0]["transform"]))
    strict = qr.decode_matrix(restored)
    assert _texts(strict) == [FLAG]
    assert strict[0]["transform"] == fx.IDENTITY and strict[0]["finder_score"] == 100


def test_repair_refuses_a_mask_pattern_that_unmasks_to_nothing():
    checker = [[(x + y) % 2 == 0 for x in range(21)] for y in range(21)]
    # The premise: under mask 0 the data region of this matrix is the all-zero codeword, which
    # passes Reed--Solomon at every level and parses as an empty payload.
    assert qr._extract(checker, 1, 0) == bytes(26)
    assert qr._deinterleave(bytes(26), 1, 0) == (bytes(19), 0)
    assert qr._payload(bytes(19), 1)["bytes"] == b""
    assert qr.decode_matrix(checker, repair=True) == []
    assert qr.force_format(checker, 0, 0) is None


def test_repair_reads_nothing_out_of_noise():
    rng = random.Random(117)
    for size in (21, 29):
        noise = [[rng.random() < 0.5 for _ in range(size)] for _ in range(size)]
        assert qr.decode_matrix(noise, repair=True) == []
    assert qr.decode_matrix([[True] * 22 for _ in range(22)], repair=True) == []


# ---- force_format -----------------------------------------------------------------------------------

def test_force_format_reads_without_the_format_string():
    clean = fx.qr_modules(FLAG, 4, "H")
    mask = qr.decode_matrix(clean)[0]["mask"]
    wrecked = fx.wreck_format(clean)
    forced = qr.force_format(wrecked, 3, mask)
    assert forced["text"] == FLAG and forced["ecl"] == "H" and forced["mask"] == mask
    assert forced["forced_format"] is True and forced["format_distance"] is None and forced["repaired"] is True
    assert qr.force_format(wrecked, "h", mask)["text"] == FLAG
    # the wrong mask or the wrong level unmasks or deinterleaves wrongly; Reed--Solomon refuses it
    assert qr.force_format(wrecked, 3, (mask + 1) % 8) is None
    assert qr.force_format(wrecked, 0, mask) is None
    assert qr.force_format([[False] * 20 for _ in range(20)], 0, 0) is None


@pytest.mark.parametrize("ecl,mask", [(4, 0), (-1, 0), (0, 8), (0, -1), ("X", 0), (True, 0), (0, True), (1.0, 0)])
def test_force_format_rejects_bad_arguments(ecl, mask):
    with pytest.raises(ValueError):
        qr.force_format(fx.qr_modules("A", 1), ecl, mask)


# ---- probe ------------------------------------------------------------------------------------------

def test_probe_names_the_damaged_parts():
    clean = fx.qr_modules(FLAG, 4, "H")
    report = qr.probe(clean)
    assert report["version"] == 4 and report["size"] == 33 and report["plausible"] is True
    assert report["damaged"] == [] and report["best"]["transform"] == fx.IDENTITY
    assert report["best"]["finders"] == {"top-left": 100, "top-right": 100, "bottom-left": 100}
    assert report["best"]["timing_score"] == 100 and report["best"]["alignment_score"] == 100
    assert report["best"]["format_distance"] == 0 and len(report["orientations"]) == 16

    one = qr.probe(fx.blank_finders(clean, corners=("top-right",)))
    assert one["damaged"] == ["finder top-right"]
    assert one["best"]["finders"]["top-left"] == 100 and one["best"]["finders"]["top-right"] < qr.FINDER_GATE

    assert qr.probe(fx.wreck_format(clean))["damaged"] == ["format"]

    no_timing = [row[:] for row in clean]
    for i in range(8, len(clean) - 8):
        no_timing[6][i] = no_timing[i][6] = False
    assert qr.probe(no_timing)["damaged"] == ["timing"]

    no_alignment = [row[:] for row in clean]
    for dy in range(-2, 3):
        for dx in range(-2, 3):
            no_alignment[26 + dy][26 + dx] = False
    assert qr.probe(no_alignment)["damaged"] == ["alignment"]


def test_probe_finds_the_orientation_and_says_when_repair_is_worth_it():
    gone = fx.blank_finders(fx.qr_modules(FLAG, 3))
    turned = fx.invert(fx.rotate(gone))
    report = qr.probe(turned)
    assert report["plausible"] is True
    assert report["damaged"] == ["finder top-left", "finder top-right", "finder bottom-left"]
    assert report["best"]["transform"] == qr.decode_matrix(turned, repair=True)[0]["transform"]
    # version 1: ten timing modules mean little alone, so flawless timing needs a format code too
    v1 = fx.blank_finders(fx.qr_modules("CSCTF{1}", 1))
    assert qr.probe(v1)["plausible"] is True
    assert qr.probe(fx.wreck_format(v1))["plausible"] is False

    rng = random.Random(5)
    noise = [[rng.random() < 0.5 for _ in range(29)] for _ in range(29)]
    assert qr.probe(noise)["plausible"] is False
    off = qr.probe([[False] * 22 for _ in range(22)])
    assert off["version"] is None and off["plausible"] is False and off["orientations"] == []


# ---- apply_transform / restore_finders / render_png -------------------------------------------------

def test_apply_transform_matches_the_decoder_orientations():
    base = fx.qr_modules(FLAG, 2)
    for transformed, transform in qr.transformations(base):
        assert qr.apply_transform(base, transform) == transformed
    with pytest.raises(ValueError):
        qr.apply_transform(base, {"rotation": 45})
    with pytest.raises(ValueError):
        qr.apply_transform(base, {"rotation": 360})


def test_restore_finders_paints_exactly_the_fixed_patterns():
    clean = fx.qr_modules(FLAG, 7, "M")
    functions = qr._function_modules(7)
    scrubbed = [row[:] for row in clean]
    size = len(clean)
    fixed = []                    # finders + separators, timing, alignment, dark module
    for y in range(size):
        for x in range(size):
            in_format = (x == 8 and (y < 9 or y >= size - 8)) or (y == 8 and (x < 9 or x >= size - 8))
            in_version = (x >= size - 11 and y < 6 and x < size - 8) or (y >= size - 11 and x < 6 and y < size - 8)
            if functions[y][x] and not (in_format and (x, y) != (8, size - 8)) and not in_version:
                fixed.append((x, y))
                scrubbed[y][x] = not clean[y][x]
    assert len(fixed) > 3 * 64
    assert qr.decode_matrix(scrubbed) == []
    restored = qr.restore_finders(scrubbed)
    assert restored == clean                       # every fixed module is back, nothing else moved
    assert scrubbed != clean                       # ... and the input was not edited in place
    with pytest.raises(ValueError):
        qr.restore_finders([[False] * 22 for _ in range(22)])


def test_render_png_draws_the_modules_at_scale_inside_the_border():
    from PIL import Image
    matrix = [[True, False, False], [False, True, False]]
    image = Image.open(io.BytesIO(qr.render_png(matrix, scale=3, border=2)))
    assert image.size == ((3 + 4) * 3, (2 + 4) * 3)
    dark = {(x, y) for y in range(image.height) for x in range(image.width) if image.getpixel((x, y)) == 0}
    expected = {(x, y) for mx, my in ((0, 0), (1, 1)) for x in range((mx + 2) * 3, (mx + 3) * 3)
                for y in range((my + 2) * 3, (my + 3) * 3)}
    assert dark == expected
    assert Image.open(io.BytesIO(qr.render_png(matrix, scale=1, border=0))).size == (3, 2)
    for bad in ({"scale": 0}, {"scale": 65}, {"border": -1}, {"border": 65}):
        with pytest.raises(ValueError):
            qr.render_png(matrix, **bad)


# ---- raster files and the CLI -----------------------------------------------------------------------

def _small_raster(tmp_path, name, matrix):
    """A version-1 symbol drawn two pixels a module: the raster sampler has little to search, so
    these tests stay short on a loaded machine (the sampler is plain Python)."""
    path = tmp_path / name
    path.write_bytes(fx.matrix_png(matrix, scale=2, border=2))
    return path


SMALL = "CSCTF{r1}"


def test_decode_path_repairs_a_raster_only_when_asked(tmp_path, capsys):
    path = _small_raster(tmp_path, "gone.png", fx.blank_finders(fx.qr_modules(SMALL, 1)))
    assert not any("bytes" in item for item in qr.decode_path(path))
    found = qr.decode_path(path, repair=True)
    assert found[0]["text"] == SMALL and found[0]["repaired"] is True

    assert qr.main([str(path)]) == 0
    assert SMALL not in capsys.readouterr().out
    assert qr.main([str(path), "--repair"]) == 0
    out = capsys.readouterr().out
    assert SMALL in out and "repaired" in out
    assert qr.main([str(path), "--repair", "--json"]) == 0
    row = json.loads(capsys.readouterr().out)["candidates"][0]
    assert row["text"] == SMALL and row["repaired"] is True and row["bytes"] == SMALL.encode().hex()

    clean = _small_raster(tmp_path, "clean.png", fx.qr_modules(SMALL, 1))
    assert qr.main([str(clean), "--repair"]) == 0
    out = capsys.readouterr().out
    assert SMALL in out and "repaired" not in out


def test_qr_decode_falls_back_to_the_repair_decode(tmp_path, monkeypatch):
    import qr_decode
    path = _small_raster(tmp_path, "gone.png", fx.blank_finders(fx.qr_modules(SMALL, 1)))
    assert qr_decode.decode_image(path) == [SMALL]                   # no camera decoder finds it; the matrix reader does
    # the fallback is what read it: without the repair the same picture gives nothing
    real = qr.decode_path
    monkeypatch.setattr(qr, "decode_path", lambda p, **kw: real(p, **{**kw, "repair": False}))
    assert qr_decode.decode_image(path) == []


def test_repair_matrices_ranks_skips_and_caps(monkeypatch):
    gone = fx.blank_finders(fx.qr_modules(FLAG, 3))
    rng = random.Random(9)
    noise = [[rng.random() < 0.5 for _ in range(29)] for _ in range(29)]
    wide = [[True] * 40 for _ in range(10)]
    tried = []
    real = qr.decode_matrix

    def spy(matrix, **kw):
        tried.append(len(matrix))
        return real(matrix, **kw)

    monkeypatch.setattr(qr, "decode_matrix", spy)
    assert _texts(qr.repair_matrices([wide, noise, gone])) == [FLAG]
    assert tried == [29]                           # the rectangle and the noise never cost a repair
    monkeypatch.setattr(qr, "REPAIR_CANDIDATES", 0)
    assert qr.repair_matrices([gone]) == []


# ---- round 1 of verification -----------------------------------------------------------------------

def test_repair_goes_to_the_candidate_with_the_most_structure_first(monkeypatch):
    """Two candidates a repair would read, one attempt allowed: it must be spent on the one with
    its finders, wherever it stands in the list."""
    intact = fx.qr_modules("CSCTF{all_structure}", 3)
    gone = fx.blank_finders(fx.qr_modules(FLAG, 3))
    assert qr.probe(intact)["plausible"] and qr.probe(gone)["plausible"]
    assert _texts(qr.repair_matrices([gone, intact], limit=1)) == ["CSCTF{all_structure}"]
    assert _texts(qr.repair_matrices([intact, gone], limit=1)) == ["CSCTF{all_structure}"]
    monkeypatch.setattr(qr, "REPAIR_CANDIDATES", 1)                  # the default limit is the constant
    assert _texts(qr.repair_matrices([gone, intact])) == ["CSCTF{all_structure}"]


def test_probe_calls_a_v3_symbol_plausible_on_its_timing_lines_alone():
    """Finders removed and the format string destroyed: from version 2 the timing lines are long
    enough to say this is a QR, and that is the gate the repair decode stands behind."""
    wrecked = fx.wreck_format(fx.blank_finders(fx.qr_modules(FLAG, 3)))
    report = qr.probe(wrecked)
    assert report["best"]["finder_score"] < 50 and report["best"]["format_distance"] > 3
    assert report["best"]["timing_score"] == 100 and report["plausible"] is True
    assert {"finder top-left", "finder top-right", "finder bottom-left", "format"} <= set(report["damaged"])
    assert _texts(qr.repair_matrices([wrecked])) == [FLAG]           # behind the gate, the repair reads it


def test_repair_limit_and_deadline_bound_the_cost(tmp_path, monkeypatch):
    gone = fx.blank_finders(fx.qr_modules(FLAG, 3))
    forced = []
    real = qr.decode_matrix

    def spy(matrix, **kw):
        forced.append(kw)
        return real(matrix, **kw)

    monkeypatch.setattr(qr, "decode_matrix", spy)
    assert qr.repair_matrices([gone], limit=0) == [] and forced == []
    assert qr.repair_matrices([gone], deadline=time.monotonic() - 1) == [] and forced == []
    assert _texts(qr.repair_matrices([gone], limit=1, deadline=time.monotonic() + 3600)) == [FLAG]
    assert forced == [{"repair": True}]
    # the deadline is looked at before each forced decode too, not only while probing: a step
    # clock that passes it after the two probes
    del forced[:]
    ticks = iter([0.0, 0.0, 100.0, 100.0])
    monkeypatch.setattr(qr.time, "monotonic", lambda: next(ticks))
    assert qr.repair_matrices([gone, fx.rotate(gone)], deadline=10.0) == [] and forced == []
    monkeypatch.undo()
    # decode_path hands both on
    path = _small_raster(tmp_path, "gone.png", fx.blank_finders(fx.qr_modules(SMALL, 1)))
    assert not any("bytes" in item for item in qr.decode_path(path, repair=True, repair_limit=0))
    assert not any("bytes" in item for item in qr.decode_path(path, repair=True, repair_deadline=time.monotonic() - 1))
    assert qr.decode_path(path, repair=True, repair_limit=1)[0]["text"] == SMALL


def test_qr_decode_says_when_the_repair_read_it_and_bounds_it(tmp_path, monkeypatch, capsys):
    import qr_decode
    path = _small_raster(tmp_path, "gone.png", fx.blank_finders(fx.qr_modules(SMALL, 1)))
    assert qr_decode.decode_image_how(path) == ([SMALL], "qr_matrix repair")
    report = qr_decode.decode(path)
    assert report["payloads"] == [SMALL] and report["read_by"] == "qr_matrix repair"
    assert qr_decode._main([str(path)]) == 0
    assert "read by the qr_matrix repair decode" in capsys.readouterr().out
    clean = tmp_path / "clean.png"
    clean.write_bytes(fx.matrix_png(fx.qr_modules(SMALL, 1), scale=8, border=4))
    payloads, how = qr_decode.decode_image_how(clean)
    assert payloads == [SMALL] and how in ("pyzbar", "zbarimg", "qr_matrix")
    assert qr_decode.decode(clean)["read_by"] == how
    assert qr_decode._main([str(clean)]) == 0
    assert "repair" not in capsys.readouterr().out
    blank = tmp_path / "blank.png"
    blank.write_bytes(fx.matrix_png([[False] * 8] * 8, scale=2, border=1))
    assert qr_decode.decode_image_how(blank) == ([], "none") and qr_decode.decode(blank)["read_by"] == "none"
    # the fallback's repair is a bounded last resort: two candidates, and a deadline
    asked = {}
    real = qr.decode_path

    def spy(p, **kw):
        asked.update(kw)
        return real(p, **kw)

    monkeypatch.setattr(qr, "decode_path", spy)
    before = time.monotonic()
    assert qr_decode.decode_image(path) == [SMALL]
    assert asked["repair"] is True and asked["repair_limit"] == qr_decode.FALLBACK_REPAIRS == 2
    assert before < asked["repair_deadline"] <= time.monotonic() + qr_decode.FALLBACK_REPAIR_SECONDS
