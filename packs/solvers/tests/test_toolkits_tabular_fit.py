"""B-093: tabular change points + exact linear fit + quantize-and-hash fingerprint.

Engine under test: solvers/toolkits/tabular_fit.py (toolkits.tabular_fit).

Every fixture is synthesised here: a piecewise-exact linear score history with a known break
(rational weights, decimal features), a probe batch, and a README written for the test.  No
real challenge file is read.  The expected fingerprints are computed independently in the test
(hashlib over a hand-written quantization), never by calling the code under test.
"""
from __future__ import annotations

import csv
import hashlib
import io
import math
import random
import subprocess
import sys
import zipfile
from fractions import Fraction as F
from pathlib import Path

import pytest

from ctf import event
from ctf.result import SolverResult

from solvers.toolkits import tabular_fit as T

CSCTF = event.load("csctf")
REPO = Path(__file__).resolve().parents[1]
N_FEAT = 10


# ------------------------------------------------------------------------- synthetic data


def _weights(rng, n=N_FEAT):
    return [F(rng.randint(-900, 900), 100) for _ in range(n + 1)]     # intercept first


def _score(w, x):
    return w[0] + sum(a * b for a, b in zip(w[1:], x))


def _features(rng, n=N_FEAT):
    return [F(rng.randint(0, 99999), 10000) for _ in range(n)]


def _dec(v: F) -> str:
    """An exact decimal string for a terminating fraction (what a CSV export would hold)."""
    sign = "-" if v < 0 else ""
    v = abs(v)
    whole, rest = divmod(v.numerator, v.denominator)
    digits = ""
    while rest and len(digits) < 30:
        rest *= 10
        d, rest = divmod(rest, v.denominator)
        digits += str(d)
    assert rest == 0, "fixture values must terminate"
    return f"{sign}{whole}" + (f".{digits}" if digits else "")


def _history(rng, breaks, rules, rows):
    """[(x, y)] with rule k in force from row breaks[k-1] on."""
    out = []
    for i in range(rows):
        k = sum(1 for b in breaks if i >= b)
        x = _features(rng)
        out.append((x, _score(rules[k], x)))
    return out


def _write_csv(path, header, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        if header:
            w.writerow(header)
        for r in rows:
            w.writerow(r)


def _challenge(tmp_path, *, seed=11, rows=240, brk=151, probes=32, readme=None, shuffle=False, name="ch"):
    """A watch-list-audit-shaped folder: history.csv (day, f0..f9, score), probes.csv, README.txt."""
    rng = random.Random(seed)
    old, new = _weights(rng), _weights(rng)
    hist = _history(rng, [brk], [old, new], rows)
    order = list(range(rows))
    if shuffle:
        rng.shuffle(order)
    d = tmp_path / name
    d.mkdir()
    feats = [f"f{j}" for j in range(N_FEAT)]
    _write_csv(d / "history.csv", ["day"] + feats + ["score"],
               [[i] + [_dec(v) for v in hist[i][0]] + [_dec(hist[i][1])] for i in order])
    px = [_features(rng) for _ in range(probes)]
    _write_csv(d / "probes.csv", ["probe_id"] + feats, [[i] + [_dec(v) for v in x] for i, x in enumerate(px)])
    if readme is not None:
        (d / "README.txt").write_text(readme)
    return d, old, new, hist, px


README = ("Each score is intercept + sum(weight_i * feature_i); exactly one deployment change, no noise.\n"
          "Response fingerprint: score each probe with the current rule, take floor(1000*score + 0.5),\n"
          "write one value per line in probe order with no trailing newline, and give the SHA-256 hex.\n")


def _expected_sha256_half_up(values, scale=1000, sep="\n", trailing=False):
    text = sep.join(str(math.floor(v * scale + F(1, 2))) for v in values) + (sep if trailing else "")
    return hashlib.sha256(text.encode()).hexdigest()


# ------------------------------------------------------------------------- exact numbers


def test_to_fraction_is_exact_and_refuses_non_numbers():
    assert T.to_fraction("0.1") == F(1, 10)
    assert T.to_fraction(" -2.50 ") == F(-5, 2)
    assert T.to_fraction("3/4") == F(3, 4)
    assert T.to_fraction("1e-3") == F(1, 1000)
    assert T.to_fraction(0.1) == F(1, 10)              # a float keeps the decimal it was written as
    assert T.to_fraction(7) == F(7)
    for bad in ("", "  ", "nan", "inf", "abc", None, float("nan"), float("inf")):
        assert T.to_fraction(bad) is None


def test_fmt_decimal_exact_when_terminating():
    assert T.fmt_decimal(F(1, 8)) == "0.125"
    assert T.fmt_decimal(F(-7, 4)) == "-1.75"
    assert T.fmt_decimal(F(1, 3)).startswith("~0.3333")


# ------------------------------------------------------------------------- exact solver


def test_exact_system_residuals_and_nullspace():
    s = T.ExactSystem(2)
    assert s.add([1, 1], 3) == 0
    assert s.rank == 1 and s.nullspace()                 # one direction still free
    assert s.add([2, 2], 7) == 1                         # 2*3 = 6, so residual 1, row not kept
    assert s.rows == 1
    assert s.add([1, -1], 1) == 0
    assert s.solution() == [F(2), F(1)] and not s.nullspace()
    assert s.add([3, 5], 11) == 0                        # 3*2 + 5*1 fits (fast path)
    assert s.add([3, 5], 12) == 1                        # off by one
    assert s.rows == 3


def test_exact_fit_recovers_rational_coefficients():
    rng = random.Random(3)
    w = _weights(rng)
    rows = [_features(rng) for _ in range(30)]
    fit = T.exact_fit(rows, [_score(w, x) for x in rows])
    assert fit.unique and list(fit.coef) == w and fit.spare == 30 - (N_FEAT + 1)


def test_exact_fit_names_the_row_with_a_residual():
    rng = random.Random(4)
    w = _weights(rng)
    rows = [_features(rng) for _ in range(20)]
    y = [_score(w, x) for x in rows]
    y[17] += F(1, 1000)
    with pytest.raises(T.NoExactFit, match="row 17"):
        T.exact_fit(rows, y)


def test_rank_deficient_fit_flags_probes_it_cannot_score():
    rng = random.Random(5)
    w = _weights(rng, 3)
    rows = [[x[0], x[1], F(2)] for x in (_features(rng, 3) for _ in range(12))]   # f2 constant
    fit = T.exact_fit(rows, [_score(w, x) for x in rows])
    assert not fit.unique and fit.rank == 3
    v, ok = fit.predict([F(1), F(1), F(2)])
    assert ok and v == _score(w, [F(1), F(1), F(2)])   # same constant: determined, and right
    _, ok = fit.predict([F(1), F(1), F(5)])
    assert not ok                                        # a new value of f2: the rows do not fix it


# ------------------------------------------------------------------------- change points


def test_find_segments_locates_the_break_and_both_rules():
    rng = random.Random(6)
    old, new = _weights(rng), _weights(rng)
    hist = _history(rng, [97], [old, new], 200)
    segs = T.find_segments([x for x, _ in hist], [y for _, y in hist])
    assert [(s.start, s.end) for s in segs] == [(0, 97), (97, 200)]
    assert list(segs[0].fit.coef) == old and list(segs[1].fit.coef) == new
    assert all(s.fit.unique for s in segs)


def test_find_segments_three_rules():
    rng = random.Random(7)
    rules = [_weights(rng) for _ in range(3)]
    hist = _history(rng, [40, 130], rules, 180)
    segs = T.find_segments([x for x, _ in hist], [y for _, y in hist])
    assert [s.start for s in segs] == [0, 40, 130]
    assert [list(s.fit.coef) for s in segs] == rules


def test_find_segments_max_segments_is_inclusive():
    # Three rules need exactly three segments: max_segments=3 accepts them, 2 refuses.
    rng = random.Random(7)
    rules = [_weights(rng) for _ in range(3)]
    hist = _history(rng, [40, 130], rules, 180)
    X, y = [x for x, _ in hist], [v for _, v in hist]
    assert [s.start for s in T.find_segments(X, y, max_segments=3)] == [0, 40, 130]
    with pytest.raises(T.NoExactFit, match="more than 2 exactly-linear segments"):
        T.find_segments(X, y, max_segments=2)
    with pytest.raises(T.NoExactFit, match="more than 1 exactly-linear segments"):
        T.find_segments(X[:130], y[:130], max_segments=1)
    assert len(T.find_segments(X[:40], y[:40], max_segments=1)) == 1

def test_find_segments_reports_slack_when_rows_fit_both_rules():
    rng = random.Random(8)
    old, new = _weights(rng), _weights(rng)
    hist = _history(rng, [60], [old, new], 120)
    # Make row 60 (the first new-rule row) also satisfy the old rule: solve its last feature.
    x = list(hist[60][0])
    rest_old = old[0] + sum(a * b for a, b in zip(old[1:-1], x[:-1]))
    rest_new = new[0] + sum(a * b for a, b in zip(new[1:-1], x[:-1]))
    x[-1] = (rest_new - rest_old) / (old[-1] - new[-1])
    hist[60] = (x, _score(new, x))
    assert _score(old, x) == _score(new, x)
    segs = T.find_segments([r for r, _ in hist], [y for _, y in hist])
    # Greedy newest-first keeps row 60 in the new segment; the slack says the break may be at 61.
    assert segs[1].start == 60 and segs[1].slack == 1 and list(segs[1].fit.coef) == new


def _fit_both_rules(old, new, x):
    """x with its last feature solved so that the old and the new rule give the same score."""
    x = list(x)
    rest_old = old[0] + sum(a * b for a, b in zip(old[1:-1], x[:-1]))
    rest_new = new[0] + sum(a * b for a, b in zip(new[1:-1], x[:-1]))
    x[-1] = (rest_new - rest_old) / (old[-1] - new[-1])
    assert _score(old, x) == _score(new, x)
    return x


def test_find_segments_slack_counts_only_consecutive_rows():
    rng = random.Random(8)
    old, new = _weights(rng), _weights(rng)
    hist = _history(rng, [60], [old, new], 120)
    for i in (60, 62):                                    # 61 sits between them and fits only the new rule
        x = _fit_both_rules(old, new, hist[i][0])
        hist[i] = (x, _score(new, x))
    assert _score(old, hist[61][0]) != hist[61][1]
    segs = T.find_segments([r for r, _ in hist], [y for _, y in hist])
    assert segs[1].start == 60 and segs[1].slack == 1     # 62 also fits the old rule, but 61 broke the run


def test_find_segments_no_slack_against_an_underdetermined_old_rule():
    rng = random.Random(31)
    old, new = _weights(rng, 2), _weights(rng, 2)        # 3 unknowns
    X = [_features(rng, 2) for _ in range(20)]           # only 2 old rows: the old rule is not pinned
    y = [_score(old if i < 2 else new, x) for i, x in enumerate(X)]
    old_fit = T.find_segments(X, y)[0].fit
    assert not old_fit.unique
    # Make the first new row agree with the old segment's particular solution (free unknowns 0).
    x = list(X[2])
    c = old_fit.coef
    x[-1] = (new[0] + new[1] * x[0] - c[0] - c[1] * x[0]) / (c[2] - new[2])
    X[2], y[2] = x, _score(new, x)
    segs = T.find_segments(X, y)
    assert [s.start for s in segs] == [0, 2] and not segs[0].fit.unique
    assert segs[0].fit.residual(X[2], y[2]) == 0          # the trap: a zero residual that proves nothing
    assert segs[1].slack == 0


def test_find_segments_refuses_noise():
    rng = random.Random(9)
    w = _weights(rng)
    rows = [_features(rng) for _ in range(200)]
    y = [_score(w, x) + F(rng.randint(-5, 5), 10 ** 6) for x in rows]
    with pytest.raises(T.NoExactFit, match="more than 8"):
        T.find_segments(rows, y)


# ------------------------------------------------------------------------- quantize + hash


@pytest.mark.parametrize("value,mode,want", [
    (F(5, 2), "half_up", 3), (F(5, 2), "half_even", 2), (F(7, 2), "half_even", 4),
    (F(-5, 2), "half_up", -2), (F(-5, 2), "half_away", -3), (F(5, 2), "half_away", 3),
    (F(-27, 10), "floor", -3), (F(-27, 10), "ceil", -2), (F(-27, 10), "trunc", -2),
    (F(27, 10), "trunc", 2),
])
def test_quantize_rounding_modes(value, mode, want):
    assert T.quantize(value, 0, mode) == want


def test_quantize_scales_by_decimals_and_rejects_unknown_mode():
    assert T.quantize(F(12345, 10000), 3, "half_up") == 1235      # 1234.5 -> 1235
    assert T.quantize(F(12345, 10000), 3, "half_even") == 1234
    with pytest.raises(ValueError):
        T.quantize(F(1), 2, "nearest")


def test_render_fixed_keeps_sign_and_padding():
    assert T.render_values([F(-1, 200), F(1, 2000), F(42)], 3, "half_up", "fixed") == ["-0.005", "0.001", "42.000"]
    assert T.render_values([F(-1, 200)], 3, "half_up", "int") == ["-5"]
    assert T.render_values([F(7, 2)], 0, "half_even", "fixed") == ["4"]


def test_fingerprint_matches_an_independent_hash():
    vals = [F(12345, 1000), F(-1, 3), F(5, 2000)]
    text = "\n".join(str(math.floor(v * 1000 + F(1, 2))) for v in vals)
    assert T.fingerprint(vals, decimals=3) == hashlib.sha256(text.encode()).hexdigest()
    md5 = hashlib.md5((",".join(["12.345", "-0.333", "0.003"]) + ",").encode()).hexdigest()
    assert T.fingerprint(vals, decimals=3, render="fixed", join=",", trailing=True, hash="md5") == md5
    assert T.fingerprint(vals, decimals=3, hexcase="upper") == hashlib.sha256(text.encode()).hexdigest().upper()


def test_readme_hints_read_the_form_and_nothing_else():
    h = T.readme_hints(README)
    assert h["hash"].value == "sha256" and h["decimals"].value == 3 and h["render"].value == "int"
    assert h["rounding"].value == "half_up" and h["join"].value == "\n" and h["trailing"].value is False
    h2 = T.readme_hints("Round each score to 2 decimal places (half to even), comma separated, "
                        "then MD5 with a trailing newline, upper-case hex.")
    assert (h2["decimals"].value, h2["render"].value, h2["rounding"].value) == (2, "fixed", "half_even")
    assert (h2["join"].value, h2["trailing"].value, h2["hash"].value, h2["hexcase"].value) == (",", True, "md5", "upper")
    assert T.readme_hints("The data are constructed numerical exports.") == {}
    assert T.readme_hints("use format %.4f then sha1")["decimals"].value == 4
    # "one value per line" is the separator even when the only "newline" is the trailing one
    assert T.readme_hints("one value per line, then a final newline")["join"].value == "\n"
    assert T.readme_hints("space-separated, no trailing newline")["join"].value == " "


def test_candidates_pinned_give_exactly_one():
    vals = [F(1, 8), F(-3, 7)]
    c = T.fingerprint_candidates(vals, fixed=dict(decimals=3, rounding="half_up", render="int", join="\n",
                                                  trailing=False, hash="sha256", hexcase="lower"))
    assert len(c) == 1 and c[0].digest == T.fingerprint(vals, decimals=3)


def test_candidates_ranked_by_readme_then_prior_and_never_collapsed_to_one():
    vals = [F(1234567, 10 ** 6), F(-7, 3), F(5, 8)]
    want = _expected_sha256_half_up(vals)
    no_hint = T.fingerprint_candidates(vals)
    assert len(no_hint) > 50 and want in [c.digest for c in no_hint]
    assert len({c.digest for c in no_hint}) == len(no_hint)                   # merged by digest
    md5_hint = T.fingerprint_candidates(vals, hints=T.readme_hints("join with commas, md5, 2 decimal places"))
    assert md5_hint[0].params["hash"] == "md5" and md5_hint[0].params["decimals"] == 2
    assert md5_hint[0].params["join"] == ","
    hinted = T.fingerprint_candidates(vals, hints=T.readme_hints(README))
    assert hinted[0].digest == want and not hinted[0].misses
    assert all(c.misses for c in hinted[1:])                                   # everything else goes against a hint


def test_candidates_readme_consistent_forms_rank_before_cheaper_misses():
    # Only the hash is hinted.  md5 with an unusual decimals value has a larger default-order sum
    # than sha256 with the most common one, but it agrees with the README, so it ranks first.
    vals = [F(1234567, 10 ** 6), F(-7, 3), F(5, 8)]
    hints = {"hash": T.Hint("md5", "md5")}
    cands = T.fingerprint_candidates(vals, hints=hints)
    misses = [bool(c.misses) for c in cands]
    first_miss = misses.index(True)
    assert first_miss > 0 and all(misses[first_miss:])      # every no-miss form before every miss
    assert all(c.params["hash"] == "md5" for c in cands[:first_miss])
    late_md5 = [c for c in cands[:first_miss] if c.params["decimals"] == 5]
    cheap_sha = [c for c in cands[first_miss:] if c.params["decimals"] == 3 and c.params["rounding"] == "half_up"]
    assert late_md5 and cheap_sha                             # the case the rank key decides


def test_candidates_count_merged_equal_forms():
    # With nothing between values, a trailing separator adds nothing: two forms, one digest.
    vals = [F(1, 8), F(-3, 7)]
    pinned = dict(decimals=3, rounding="half_up", render="int", join="", hash="sha256", hexcase="lower")
    c = T.fingerprint_candidates(vals, fixed=pinned)
    assert len(c) == 1 and c[0].also == 1 and c[0].params["trailing"] is False
    assert "+1 equal form(s)" in c[0].describe()
    one = T.fingerprint_candidates(vals, fixed=dict(pinned, join=","))
    assert len(one) == 2 and all(x.also == 0 for x in one)


def test_candidates_reject_unknown_parameter():
    with pytest.raises(ValueError):
        T.fingerprint_candidates([F(1)], fixed={"salt": "x"})


# ------------------------------------------------------------------------- tables


def test_read_csv_header_headerless_and_delimiters(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("A;B ;score\n1;2.5;3\n4;5;6\n")
    t = T.read_csv(p)
    assert t.columns == ["a", "b", "score"] and t.rows[0] == ["1", "2.5", "3"]
    q = tmp_path / "b.tsv"
    q.write_text("1\t2\n3\t4\n")
    t2 = T.read_csv(q)
    assert t2.columns == ["c0", "c1"] and len(t2.rows) == 2
    d = tmp_path / "dup.csv"
    d.write_text("x,X\n1,2\n")
    with pytest.raises(T.TabularError, match="duplicate"):
        T.read_csv(d)


@pytest.mark.needs_tool("py:numpy")
def test_read_npz_matrix_vector_structured_and_columns(tmp_path):
    import numpy as np
    p = tmp_path / "d.npz"
    np.savez(p, X=np.arange(12.0).reshape(4, 3), y=np.array([1.5, 2.5, 3.5, 4.5]),
             X_probe=np.ones((2, 3)), a=np.array([1, 2, 3, 4, 5]), b=np.array([0.25] * 5))
    tables = {t.name: t for t in T.read_npz(p)}
    assert tables["d.npz:X"].columns == ["f0", "f1", "f2", "y"]
    assert T.to_fraction(tables["d.npz:X"].rows[1][3]) == F(5, 2)
    assert tables["d.npz:X_probe"].columns == ["f0", "f1", "f2"]
    assert tables["d.npz:a,b"].columns == ["a", "b"] and T.to_fraction(tables["d.npz:a,b"].rows[0][1]) == F(1, 4)
    s = tmp_path / "s.npz"
    np.savez(s, rec=np.array([(1, 2.5)], dtype=[("u", "i8"), ("score", "f8")]))
    assert T.read_npz(s)[0].columns == ["u", "score"]


@pytest.mark.needs_tool("py:numpy")
def test_read_npz_refuses_object_arrays(tmp_path):
    import numpy as np
    p = tmp_path / "evil.npz"
    np.savez(p, x=np.array([{"a": 1}], dtype=object))       # pickled object array
    with pytest.raises(T.TabularError, match="allow_pickle=False"):
        T.read_npz(p)


def test_find_files_dedupes_copies_and_skips_recon(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "unpacked").mkdir()
    (tmp_path / "recon").mkdir()
    (tmp_path / "files" / "h.csv").write_text("a,b\n1,2\n")
    (tmp_path / "unpacked" / "h.csv").write_text("a,b\n1,2\n")
    (tmp_path / "recon" / "out.csv").write_text("x\n1\n")
    found = T.find_files(tmp_path, (".csv",))
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["files/h.csv"]


def test_assemble_picks_target_features_and_probe_rows_in_one_file(tmp_path):
    p = tmp_path / "all.csv"
    p.write_text("id,a,b,score\n1,1,2,5\n2,2,1,4\n3,3,3,\n")
    ds = T.assemble([T.read_csv(p)])
    assert ds.target == "score" and ds.features == ["a", "b"]
    assert ds.y == [5, 4] and ds.probes == [[3, 3]]


def test_assemble_without_target_or_pair_is_named(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n")
    with pytest.raises(T.TabularError, match="target"):
        T.assemble([T.read_csv(p)])


# ------------------------------------------------------------------------- solve end to end


def test_solve_scores_probes_with_latest_rule_and_ranks_readme_form_first(tmp_path):
    d, old, new, _hist, px = _challenge(tmp_path, readme=README)
    res = T.solve(d, CSCTF)
    assert res.status == "candidate", res.notes
    want = _expected_sha256_half_up([_score(new, x) for x in px])
    assert res.flags[0] == want
    assert want != _expected_sha256_half_up([_score(old, x) for x in px])
    assert 1 < len(res.flags) <= T.DEFAULT_MAX_CANDIDATES          # ranked, never one silent pick
    assert "change point(s) at row(s) 151" in res.notes
    fits = [e for e in res.evidence if e.kind == "fit"]
    assert len(fits) == 2 and "rows 151..239" in fits[1].detail
    SolverResult.from_json(res.to_json())


def test_solve_with_all_parameters_pinned_returns_that_form_only(tmp_path):
    d, _old, new, _hist, px = _challenge(tmp_path)
    res = T.solve(d, CSCTF, decimals="2", rounding="half_up", render="int", join="comma", trailing="true",
                  hash="sha256", hexcase="lower")
    assert res.status == "candidate"
    assert res.flags == (_expected_sha256_half_up([_score(new, x) for x in px], scale=100, sep=",", trailing=True),)


def test_solve_sorts_a_shuffled_history_by_its_time_column(tmp_path):
    d, _old, new, _hist, px = _challenge(tmp_path, shuffle=True, readme=README)
    res = T.solve(d, CSCTF)
    assert res.status == "candidate" and "history ordered by 'day'" in res.notes
    assert res.flags[0] == _expected_sha256_half_up([_score(new, x) for x in px])
    # In file order the shuffled rows are not two clean segments.
    res2 = T.solve(d, CSCTF, order="file")
    assert res2.status == "none" and "segments" in res2.notes


def test_solve_change_count_mismatch_is_unsure(tmp_path):
    d, *_ = _challenge(tmp_path, readme=README)
    assert T.solve(d, CSCTF, changes="1").status == "candidate"
    res = T.solve(d, CSCTF, changes="2")
    assert res.status == "unsure" and "the brief says 2" in res.notes and not res.flags


def test_solve_short_latest_segment_is_unverified(tmp_path):
    # 12 newest rows for 11 unknowns: one spare row, below the default of 2.
    d, *_ = _challenge(tmp_path, rows=200, brk=188, readme=README)
    res = T.solve(d, CSCTF)
    assert res.status == "unsure" and "unverified" in res.notes
    assert T.solve(d, CSCTF, min_check_rows="1").status == "candidate"


def test_solve_without_probes_reports_the_rule(tmp_path):
    d, _old, new, _hist, _px = _challenge(tmp_path)
    (d / "probes.csv").unlink()
    res = T.solve(d, CSCTF)
    assert res.status == "unsure" and "no probe rows" in res.notes
    assert "intercept=" + T.fmt_fraction(new[0]) in [e for e in res.evidence if e.kind == "fit"][-1].detail


def test_solve_noisy_history_is_none_with_reason(tmp_path):
    rng = random.Random(21)
    w = _weights(rng)
    d = tmp_path / "noisy"
    d.mkdir()
    rows = []
    for i in range(150):
        x = _features(rng)
        rows.append([i] + [_dec(v) for v in x] + [_dec(_score(w, x) + F(rng.randint(1, 9), 10 ** 5))])
    _write_csv(d / "history.csv", ["day"] + [f"f{j}" for j in range(N_FEAT)] + ["score"], rows)
    _write_csv(d / "probes.csv", ["probe_id"] + [f"f{j}" for j in range(N_FEAT)], [[0] + ["1"] * N_FEAT])
    res = T.solve(d, CSCTF)
    assert res.status == "none" and "noisy" in res.notes and not res.flags


def _noisy_dir(tmp_path, rows, n_feat, seed=21):
    rng = random.Random(seed)
    w = _weights(rng, n_feat)
    d = tmp_path / f"noisy{rows}"
    d.mkdir()
    out = []
    for i in range(rows):
        x = _features(rng, n_feat)
        out.append([i] + [_dec(v) for v in x] + [_dec(_score(w, x) + F(rng.randint(1, 9), 10 ** 5))])
    feats = [f"f{j}" for j in range(n_feat)]
    _write_csv(d / "history.csv", ["day"] + feats + ["score"], out)
    _write_csv(d / "probes.csv", ["probe_id"] + feats, [[0] + ["1"] * n_feat])
    return d


def test_solve_short_noisy_history_says_noisy(tmp_path):
    # 40 noisy rows, 5 unknowns: exactly 8 segments of 5 rows each, none with a spare row.
    res = T.solve(_noisy_dir(tmp_path, 40, 4), CSCTF)
    assert res.status == "unsure" and not res.flags
    assert "8 segment(s)" in res.notes and "noisy or rounded" in res.notes
    # A real change whose latest segment has 0 spare rows (11 rows, 11 unknowns) is unverified,
    # but the long first segment checks out, so it is not called noise.
    d, *_ = _challenge(tmp_path, rows=200, brk=189, readme=README)
    res2 = T.solve(d, CSCTF)
    assert res2.status == "unsure" and "0 spare row(s)" in res2.notes and "noisy" not in res2.notes


def test_solve_single_segment_without_spare_rows_is_not_called_noise(tmp_path):
    # 5 rows, 4 features + intercept = 5 unknowns: one segment, 0 spare rows.  With
    # min_check_rows=0 the user accepts that; one segment is not "a run of rule changes".
    rng = random.Random(25)
    w = _weights(rng, 4)
    d = tmp_path / "one"
    d.mkdir()
    X = [_features(rng, 4) for _ in range(5)]
    feats = [f"f{j}" for j in range(4)]
    _write_csv(d / "history.csv", ["day"] + feats + ["score"],
               [[i] + [_dec(v) for v in x] + [_dec(_score(w, x))] for i, x in enumerate(X)])
    px = [_features(rng, 4) for _ in range(3)]
    _write_csv(d / "probes.csv", ["probe_id"] + feats, [[i] + [_dec(v) for v in x] for i, x in enumerate(px)])
    res = T.solve(d, CSCTF, min_check_rows="0", **PINNED)
    assert "1 segment(s)" in res.notes and "noisy or rounded" not in res.notes
    assert res.status == "candidate", res.notes
    assert res.flags == (_expected_sha256_half_up([_score(w, x) for x in px]),)
    # The default min_check_rows still flags it, as unverified (not as noise).
    res2 = T.solve(d, CSCTF, **PINNED)
    assert res2.status == "unsure" and "0 spare row(s)" in res2.notes and "noisy" not in res2.notes

def test_solve_undetermined_probe_is_unsure(tmp_path):
    rng = random.Random(22)
    w = _weights(rng, 3)
    d = tmp_path / "rank"
    d.mkdir()
    rows = []
    for i in range(40):
        x = [_features(rng, 1)[0], _features(rng, 1)[0], F(3)]       # c constant in the history
        rows.append([i, _dec(x[0]), _dec(x[1]), "3", _dec(_score(w, x))])
    _write_csv(d / "history.csv", ["day", "a", "b", "c", "score"], rows)
    _write_csv(d / "probes.csv", ["a", "b", "c"], [["1", "2", "3"], ["1", "2", "4"]])
    res = T.solve(d, CSCTF)
    assert res.status == "unsure" and "not determined" in res.notes and "probes.csv#2" in res.notes


def test_solve_falls_back_to_id_columns_when_the_rule_uses_them(tmp_path):
    rng = random.Random(23)
    d = tmp_path / "idx"
    d.mkdir()
    rows = []
    for i in range(30):
        a = _features(rng, 1)[0]
        rows.append([i, _dec(a), _dec(F(1, 2) + 2 * a + F(3, 4) * i)])   # 'index' is a real feature here
    _write_csv(d / "history.csv", ["index", "a", "score"], rows)
    _write_csv(d / "probes.csv", ["index", "a"], [["100", "1"]])
    res = T.solve(d, CSCTF, decimals="2", rounding="half_up", render="int", join="\n", trailing="false",
                  hash="sha256", hexcase="lower")
    assert res.status == "candidate" and "they are features here" in res.notes
    want = hashlib.sha256(str(math.floor((F(1, 2) + 2 + F(3, 4) * 100) * 100 + F(1, 2))).encode()).hexdigest()
    assert res.flags == (want,)


@pytest.mark.needs_tool("py:numpy")
def test_solve_npz_history_and_probes(tmp_path):
    import numpy as np
    rng = random.Random(24)
    old, new = _weights(rng, 4), _weights(rng, 4)
    hist = []
    for i in range(80):
        x = [F(rng.randint(0, 999), 8) for _ in range(4)]               # binary fractions: exact in float64
        hist.append((x, _score(old if i < 33 else new, x)))
    px = [[F(rng.randint(0, 999), 8) for _ in range(4)] for _ in range(5)]
    d = tmp_path / "npz"
    d.mkdir()
    np.savez(d / "audit.npz", X=np.array([[float(v) for v in x] for x, _ in hist]),
             score=np.array([float(y) for _, y in hist]), X_probe=np.array([[float(v) for v in x] for x in px]))
    res = T.solve(d, CSCTF, decimals="3", rounding="half_up", render="int", join="\n", trailing="false",
                  hash="sha256", hexcase="lower")
    assert res.status == "candidate", res.notes
    assert res.flags == (_expected_sha256_half_up([_score(new, x) for x in px]),)
    assert "change point(s) at row(s) 33" in res.notes


def _npz_data(seed, rows, n_probe, brk):
    rng = random.Random(seed)
    old, new = _weights(rng, 4), _weights(rng, 4)
    X = [[F(rng.randint(0, 999), 8) for _ in range(4)] for _ in range(rows)]
    y = [_score(old if i < brk else new, x) for i, x in enumerate(X)]
    P = [[F(rng.randint(0, 999), 8) for _ in range(4)] for _ in range(n_probe)]
    return new, X, y, P


PINNED = dict(decimals="3", rounding="half_up", render="int", join="\n", trailing="false",
              hash="sha256", hexcase="lower")


@pytest.mark.needs_tool("py:numpy")
@pytest.mark.parametrize("probe_name,hist_name", [("probes", "X"), ("X_test", "X_train"), ("audit", "history")])
def test_solve_npz_equal_length_probes_stored_first(tmp_path, probe_name, hist_name):
    # The probe matrix has as many rows as the history and comes first in the archive: the target
    # still joins the history matrix (by name), never the probes.
    import numpy as np
    new, X, y, P = _npz_data(41, 40, 40, 17)
    d = tmp_path / "eq"
    d.mkdir()
    arrs = {probe_name: np.array([[float(v) for v in r] for r in P]),
            hist_name: np.array([[float(v) for v in r] for r in X]),
            "y": np.array([float(v) for v in y])}
    np.savez(d / "audit.npz", **arrs)
    with np.load(d / "audit.npz") as z:
        assert z.files[0] == probe_name                    # the order that used to mis-pair
    res = T.solve(d, CSCTF, **PINNED)
    assert res.status == "candidate", res.notes
    assert res.flags == (_expected_sha256_half_up([_score(new, x) for x in P]),)
    assert f"'y' joined to '{hist_name}', not '{probe_name}'" in res.notes and "by the array names" in res.notes


@pytest.mark.needs_tool("py:numpy")
def test_read_npz_equal_length_neutral_names_says_it_guessed(tmp_path):
    import numpy as np
    p = tmp_path / "n.npz"
    np.savez(p, M=np.zeros((3, 2)), N=np.ones((3, 2)), s=np.array([1.0, 2.0, 3.0]))
    tables = {t.name: t for t in T.read_npz(p)}
    assert tables["n.npz:M"].columns == ["f0", "f1", "s"] and tables["n.npz:N"].columns == ["f0", "f1"]
    assert any("by array order" in n for n in tables["n.npz:M"].notes)
    assert T._array_role("X_probe") == 2 and T._array_role("X") == 0 and T._array_role("latest") == 1


@pytest.mark.needs_tool("py:numpy")
@pytest.mark.parametrize("probe_name,hist_name", [("B", "A"), ("M", "N")])
def test_solve_npz_neutral_names_probes_first_pairs_by_exact_fit(tmp_path, probe_name, hist_name):
    # Neutral names and equal row counts, probes stored first: array order would join y to the
    # probes; the pairing that fits y exactly (2 segments) wins and the note says how.
    import numpy as np
    new, X, y, P = _npz_data(43, 40, 40, 17)
    d = tmp_path / "neutral"
    d.mkdir()
    np.savez(d / "audit.npz", **{probe_name: np.array([[float(v) for v in r] for r in P]),
                                 hist_name: np.array([[float(v) for v in r] for r in X]),
                                 "y": np.array([float(v) for v in y])})
    with np.load(d / "audit.npz") as z:
        assert z.files[0] == probe_name
    tables = {t.name: t for t in T.read_npz(d / "audit.npz")}
    assert tables[f"audit.npz:{hist_name}"].columns[-1] == "y"
    assert "y" not in tables[f"audit.npz:{probe_name}"].columns
    res = T.solve(d, CSCTF, **PINNED)
    assert res.status == "candidate", res.notes
    assert res.flags == (_expected_sha256_half_up([_score(new, x) for x in P]),)
    assert f"'y' joined to '{hist_name}', not '{probe_name}'" in res.notes and "by exact fit" in res.notes
    assert "2 exactly-linear segment(s)" in res.notes


@pytest.mark.needs_tool("py:numpy")
def test_pairing_fit_ranks_the_true_history_first():
    import numpy as np
    _new, X, y, P = _npz_data(44, 40, 40, 17)
    hist = T._pairing_fit(np.array([[float(v) for v in r] for r in X]), np.array([float(v) for v in y]))
    wrong = T._pairing_fit(np.array([[float(v) for v in r] for r in P]), np.array([float(v) for v in y]))
    assert hist == (2, -(40 - 2 * 5))
    assert wrong is None or wrong > hist
    assert T._pairing_fit(np.array([[1.0, float("nan")]]), np.array([1.0])) is None

@pytest.mark.needs_tool("py:numpy")
def test_to_fraction_float32_keeps_the_written_decimal():
    import numpy as np
    assert T.to_fraction(np.float32(0.1)) == F(1, 10)
    assert T.to_fraction(np.float16(0.5)) == F(1, 2)
    assert T.to_fraction(np.float64(0.1)) == F(1, 10)
    assert T.to_fraction(np.float32("nan")) is None and T.to_fraction(np.float32("inf")) is None


@pytest.mark.needs_tool("py:numpy")
@pytest.mark.parametrize("dtype", ["float32", "float16"])
def test_solve_npz_narrow_float_export(tmp_path, dtype):
    # Decimal features (0.1, 0.37, ...) that float32 cannot hold exactly: the fit must see the
    # decimals the author wrote, not float32's binary value widened to float64.
    import numpy as np
    rng = random.Random(42)
    old, new = [F(1, 2), F(3), F(-2), F(1, 4)], [F(-1), F(5, 2), F(1), F(-3, 2)]
    # Within each dtype's round-trip digits (float32: 6, float16: 3): features x.xx / x.x, and for
    # float32 targets of at most 6 significant digits.
    scale = 10 if dtype == "float16" else 100
    feat = lambda: F(rng.randint(0, 9 * scale + scale - 1), scale)   # noqa: E731
    X = [[feat() for _ in range(3)] for _ in range(30)]
    y = [_score(old if i < 12 else new, x) for i, x in enumerate(X)]
    P = [[feat() for _ in range(3)] for _ in range(4)]
    assert any(np.dtype(dtype).type(float(v)).item() != float(v) for r in X for v in r)   # inexact in binary
    d = tmp_path / dtype
    d.mkdir()
    # float16 cannot hold the targets' digits, so there the target column stays float64.
    ys = np.array([float(v) for v in y], dtype="float64" if dtype == "float16" else dtype)
    np.savez(d / "h.npz", X=np.array([[float(v) for v in r] for r in X], dtype=dtype), y=ys,
             X_probe=np.array([[float(v) for v in r] for r in P], dtype=dtype))
    res = T.solve(d, CSCTF, **PINNED)
    assert res.status == "candidate", res.notes
    assert res.flags == (_expected_sha256_half_up([_score(new, x) for x in P]),)
    assert "change point(s) at row(s) 12" in res.notes


def test_solve_npz_without_numpy_is_blocked(tmp_path, monkeypatch):
    d = tmp_path / "nonp"
    d.mkdir()
    (d / "a.npz").write_bytes(b"PK\x03\x04 not really")

    def no_numpy():
        raise T.TabularError("numpy is required to read .npz tables (pip install numpy)")
    monkeypatch.setattr(T, "_require_numpy", no_numpy)
    res = T.solve(d, CSCTF)
    assert res.status == "blocked" and "numpy" in res.notes


def test_solve_no_tables_and_bad_options(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "note.txt").write_text("nothing tabular")
    res = T.solve(empty, CSCTF)
    assert res.status == "none" and "no CSV/TSV/NPZ" in res.notes
    d, *_ = _challenge(tmp_path)
    for bad in ({"rounding": "nearest"}, {"hash": "crc32"}, {"decimals": "x"}, {"intercept": "maybe"},
                {"max_segments": "0"}):
        r = T.solve(d, CSCTF, **bad)
        assert r.status == "blocked" and r.notes, bad


def test_solve_without_intercept_option(tmp_path):
    rng = random.Random(25)
    d = tmp_path / "noint"
    d.mkdir()
    w = [F(0)] + [F(rng.randint(-9, 9), 4) for _ in range(3)]
    rows = []
    for i in range(20):
        x = _features(rng, 3)
        rows.append([i] + [_dec(v) for v in x] + [_dec(_score(w, x))])
    _write_csv(d / "history.csv", ["day", "a", "b", "c", "score"], rows)
    _write_csv(d / "probes.csv", ["a", "b", "c"], [["1", "1", "1"]])
    res = T.solve(d, CSCTF, intercept="false")
    assert res.status == "candidate"
    fit = [e for e in res.evidence if e.kind == "fit"][0].detail
    assert "intercept=" not in fit and "a=" + T.fmt_fraction(w[1]) in fit


def test_solve_options_shape_the_columns_and_the_list(tmp_path):
    d, _old, new, _hist, px = _challenge(tmp_path, readme=README)
    # An extra history-only column makes the target ambiguous until it is named.
    rows = list(csv.reader(open(d / "history.csv")))
    rows[0].append("version")
    for i, r in enumerate(rows[1:]):
        r.append(str(1 + (i >= 151)))
    _write_csv(d / "history.csv", None, rows)
    byname = T.solve(d, CSCTF, max_candidates="1")
    assert byname.status == "candidate" and "score-like name among the history-only columns" in byname.notes
    named = T.solve(d, CSCTF, target="score", max_candidates="3")
    assert named.flags[:1] == byname.flags
    assert named.status == "candidate" and len(named.flags) == 3
    assert "dropped version" in named.notes
    assert named.flags[0] == _expected_sha256_half_up([_score(new, x) for x in px])
    # Excluding a real feature breaks the exact fit; naming the features restores it.
    assert T.solve(d, CSCTF, target="score", exclude="f3").status == "none"
    feats = ",".join(f"f{j}" for j in range(N_FEAT))
    assert T.solve(d, CSCTF, target="score", features=feats, max_candidates="1").flags == named.flags[:1]


def test_two_unnamed_history_only_columns_are_ambiguous(tmp_path):
    h = tmp_path / "h.csv"
    h.write_text("a,b,s,aux\n1,2,3,4\n2,1,4,4\n")
    q = tmp_path / "q.csv"
    q.write_text("a,b\n1,1\n")
    with pytest.raises(T.TabularError, match="several columns could be the target"):
        T.assemble([T.read_csv(h), T.read_csv(q)])
    assert T.assemble([T.read_csv(h), T.read_csv(q)], target="s").features == ["a", "b"]


def test_readme_is_the_hint_source_when_present(tmp_path):
    d, *_ = _challenge(tmp_path, readme="Fingerprint: MD5 of the comma separated values.")
    (d / "SHA256SUMS.txt").write_text("sha-256 of the zip: 00ff\n")
    text, names = T.load_readme_text(d)
    assert names == ["README.txt"] and T.readme_hints(text)["hash"].value == "md5"
    (d / "README.txt").unlink()
    text, names = T.load_readme_text(d)
    assert names == ["SHA256SUMS.txt"] and T.readme_hints(text)["hash"].value == "sha256"


def test_more_readme_scale_forms():
    assert T.readme_hints("take score * 100 then floor")["decimals"].value == 2
    assert T.readme_hints("round to the nearest 0.01")["decimals"].value == 2
    assert T.readme_hints("round to the nearest 0.01")["render"].value == "fixed"
    assert T.readme_hints("values multiplied by 10000 and truncated")["decimals"].value == 4
    assert T.readme_hints("values multiplied by 10000 and truncated")["rounding"].value == "trunc"


def test_exact_system_residual_probe_does_not_change_the_system():
    s = T.ExactSystem(2)
    s.add([1, 0], 2)
    assert s.residual([0, 1], 5) is None          # a new direction: no residual yet
    s.add([0, 1], 5)
    assert s.residual([1, 1], 8) == 1 and s.rows == 2


# ------------------------------------------------------------------------- CLI, routing, intake


def test_main_prints_solver_result_json(tmp_path, capsys):
    d, _old, new, _hist, px = _challenge(tmp_path, readme=README)
    code = T.main([str(d / "history.csv"), "--event", "csctf"])
    res = SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 0 and res.flags[0] == _expected_sha256_half_up([_score(new, x) for x in px])
    assert T.main([str(tmp_path / "missing"), "--event", "csctf"]) == 2
    assert T.main(["--opt", "decimals"]) == 2
    assert T.main([str(d), "--opt", "nokv", "--event", "csctf"]) == 2


def test_script_run_bootstraps_ctf_import(tmp_path):
    d, _old, new, _hist, px = _challenge(tmp_path, readme=README)
    script = REPO / "solvers" / "toolkits" / "tabular_fit.py"
    proc = subprocess.run([sys.executable, "-I", str(script), str(d), "--event", "csctf"],
                          cwd=tmp_path, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    res = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    assert res.flags[0] == _expected_sha256_half_up([_score(new, x) for x in px])


def test_router_sends_rule_change_briefs_here():
    from ctf.engines import router
    brief = ("Responders kept the scoring history across a rule change and a fresh batch of audit probes. "
             "Reconstruct the current rule and compute the response fingerprint defined in README.txt.")
    ids = [h.manifest.id for h in router.route("misc", brief)]
    assert ids and ids[0] == "toolkits.tabular_fit"
    assert "toolkits.tabular_fit" not in [h.manifest.id for h in router.route("misc", "decode this morse audio")]


def test_manifest_adapts_tables_for_intake():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.tabular_fit"]
    assert m.intake.select == "files" and m.intake.run == "challenge" and m.cost_class == "cheap"
    assert m.entry.kind != "cli"
    assert E.files_matching(m.intake.match, [(Path("history.csv"), b"day,f0\n")])
    assert E.files_matching(m.intake.match, [(Path("audit.npz"), b"PK\x03\x04")])
    assert not E.files_matching(m.intake.match, [(Path("notes.txt"), b"hello")])


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


def test_intake_runs_on_a_zipped_audit_export(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    src, _old, new, _hist, px = _challenge(tmp_path, readme=README, name="src")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in ("history.csv", "probes.csv", "README.txt"):
            z.write(src / n, f"audit/{n}")
    ch = Challenge(id="9989", name="Synthetic Audit", category="misc", points=100,
                   description="Reconstruct the current rule after the rule change.",
                   files=(FileRef("audit.zip"),))
    rep = I.intake_one("9989", CSCTF, adapter=_Adapter(ch, {"audit.zip": buf.getvalue()}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.tabular_fit"]
    assert runs and runs[0].status == "ok", [(r.engine, r.status) for r in rep.runs]
    assert runs[0].result_status == "candidate"
    out = (rep.dir / "recon" / "engines" / "toolkits.tabular_fit" / "out.txt").read_text()
    res = SolverResult.from_json(out.strip().splitlines()[-1])
    assert res.flags[0] == _expected_sha256_half_up([_score(new, x) for x in px])
    # A bare digest is not in the event flag format, so intake merges no flag from it and never
    # reports the challenge solved; the ranked fingerprints wait in the engine's output.
    assert rep.status != "solved" and not rep.flags


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
