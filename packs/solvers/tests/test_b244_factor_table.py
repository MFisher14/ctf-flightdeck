"""B-244: the offline FactorDB-style factor table (solvers/common/factor_table.py) and its path
(ctf.paths.factor_table_path). Tables are built inside each test from synthetic dumps; the real table
outside the repo is read only by the needs_realdata test at the bottom."""
from __future__ import annotations

import json
import random
import sqlite3

import pytest

import factor_table as FT
from ctf import env, paths


def _prime(rng, bits):
    import sympy
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if sympy.isprime(c):
            return c


@pytest.fixture
def no_table_env(monkeypatch, tmp_path):
    for name in ("CTF_FACTOR_TABLE", *env.legacy_names("CTF_FACTOR_TABLE")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "no-realdata"))


def _dump(tmp_path, lines, name="dump.txt"):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return p


# ---- parsing ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("line, want", [
    ("15 = 3 * 5", (15, (3, 5))),
    ("15: 3, 5", (15, (3, 5))),
    ("15 3 5", (15, (3, 5))),
    ("15,3,5", (15, (3, 5))),
    ("0xf = 0x3 * 5", (15, (3, 5))),
    ("72 = 2^3 * 3^2", (72, (2, 2, 2, 3, 3))),
    ('{"n": 21, "factors": [3, "7"]}', (21, (3, 7))),
    ("1_000_003 = 1_000_003 * 1", (1000003, (1000003, 1))),       # parsed; _check rejects it later
])
def test_parse_line_formats(line, want):
    assert FT.parse_line(line) == want


@pytest.mark.parametrize("line", ["", "   ", "# 15 = 3 * 5"])
def test_parse_line_skips_blank_and_comments(line):
    assert FT.parse_line(line) is None


@pytest.mark.parametrize("line", ["15", "15 = 3 * x5", "2^3 = 8 * 1", "15 = 3 ^ 0", '{"n": 15}',
                                  "n = 3 * 5", "15 = 0xg3 * 5"])
def test_parse_line_rejects_malformed(line):
    with pytest.raises(ValueError):
        FT.parse_line(line)


# ---- build ---------------------------------------------------------------------------------------------

def test_build_stores_sound_rows_and_rejects_the_rest(tmp_path):
    rng = random.Random(244)
    p, q, r = _prime(rng, 64), _prime(rng, 64), _prime(rng, 64)
    src = _dump(tmp_path, [
        "# known keys",
        f"{p * q} = {p} * {q}",
        f"{p * q} = {q} * {p}",                  # duplicate n
        f"{p * q * r} = {p * q} * {r}",          # composite factor left: CF
        f"{p * q + 2} = {p} * {q}",              # wrong product
        f"{p} = {p}",                            # a single factor
        f"{p} = {p} * 1",                        # factor 1
        "garbage line",
    ])
    out = tmp_path / "t.sqlite"
    rep = FT.build(out, [src])
    assert (rep["added"], rep["duplicates"], rep["rejected"], rep["rows"]) == (2, 1, 4, 2)
    assert any(":5: factors do not multiply to n" in x for x in rep["rejected_first"])
    assert any(":6: a single factor" in x for x in rep["rejected_first"])
    assert any(":7: a factor at or below 1" in x for x in rep["rejected_first"])
    assert any(":8: unexpected characters" in x for x in rep["rejected_first"])
    assert rep["primes"] == 3                    # p, q (from row 1) and r (row 3); p*q is not prime
    with FT.FactorTable(out) as t:
        e1 = t.lookup(p * q)
        assert e1.factors == tuple(sorted((p, q))) and e1.status == "FF" and e1.source == "dump.txt"
        e2 = t.lookup(p * q * r)
        assert e2.status == "CF" and e2.factors == tuple(sorted((p * q, r)))
        assert t.lookup(p * r) is None
        assert t.status() == {"table": str(out), "rows": 2, "fully_factored": 1, "primes": 3}


def test_build_extends_an_existing_table(tmp_path):
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5"], "a.txt")])
    rep = FT.build(out, [_dump(tmp_path, ["21 = 3 * 7", "15 = 3 * 5"], "b.txt")])
    assert (rep["added"], rep["duplicates"], rep["rows"]) == (1, 1, 2)
    with FT.FactorTable(out) as t:
        assert t.lookup(15).source == "a.txt" and t.lookup(21).source == "b.txt"


# ---- lookup ---------------------------------------------------------------------------------------------

def test_shared_prime_found_through_a_stored_prime(tmp_path):
    rng = random.Random(7)
    p, q, s = _prime(rng, 80), _prime(rng, 80), _prime(rng, 80)
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, [f"{p * q} = {p} * {q}"])])
    with FT.FactorTable(out) as t:
        assert t.lookup(p * s) is None                       # never stored itself
        e = t.find(p * s)
        assert e.how == "shared-prime" and e.factors == tuple(sorted((p, s))) and e.status == "FF"
        assert t.shared_factor(_prime(rng, 80) * _prime(rng, 80)) is None
        assert t.find(p * q).how == "table"


def test_a_corrupt_row_raises_never_a_silent_miss(tmp_path):
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5", "21 = 3 * 7"])])
    db = sqlite3.connect(out)
    db.execute("UPDATE factors SET factors='3,7' WHERE n='f'")       # 15 now says 3 * 7
    db.execute("UPDATE factors SET factors='zz' WHERE n='15'")       # 21 (0x15) holds junk
    db.commit()
    db.close()
    with FT.FactorTable(out) as t:
        with pytest.raises(FT.TableCorrupt, match="factors do not multiply"):
            t.lookup(15)
        with pytest.raises(FT.TableCorrupt, match="not hex"):
            t.lookup(21)


def test_lookup_rejects_bad_n(tmp_path):
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5"])])
    with FT.FactorTable(out) as t:
        for bad in (3, "15", 1.5):
            with pytest.raises(ValueError):
                t.lookup(bad)


def test_a_file_that_is_not_a_factor_table_is_refused(tmp_path):
    junk = tmp_path / "junk.sqlite"
    junk.write_bytes(b"not sqlite at all" * 10)
    with pytest.raises(FT.TableCorrupt):
        FT.FactorTable(junk)
    other = tmp_path / "other.sqlite"
    db = sqlite3.connect(other)
    db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO meta VALUES('schema', '99')")
    db.commit()
    db.close()
    with pytest.raises(FT.TableCorrupt, match="schema '99'"):
        FT.FactorTable(other)


def test_the_table_is_opened_read_only_even_with_uri_characters_in_the_path(tmp_path):
    folder = tmp_path / "a?b#c"
    folder.mkdir()
    out = folder / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5"])])
    with FT.FactorTable(out) as t:
        assert t.lookup(15).factors == (3, 5)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            t._db.execute("DELETE FROM factors")


# ---- where the table comes from ---------------------------------------------------------------------------

def test_no_table_configured_fails_loudly_naming_the_variable(no_table_env):
    assert paths.factor_table_path() is None
    with pytest.raises(FT.TableMissing, match="CTF_FACTOR_TABLE"):
        FT.FactorTable()


def test_env_variable_names_the_table_and_a_typo_is_not_no_table(no_table_env, monkeypatch, tmp_path):
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5"])])
    monkeypatch.setenv("CTF_FACTOR_TABLE", str(out))
    assert paths.factor_table_path() == out.resolve()
    with FT.FactorTable() as t:
        assert t.lookup(15).factors == (3, 5)
    monkeypatch.setenv("CTF_FACTOR_TABLE", str(tmp_path / "typo.sqlite"))
    with pytest.raises(FileNotFoundError, match="CTF_FACTOR_TABLE"):
        paths.factor_table_path()
    with pytest.raises(FT.TableMissing, match="CTF_FACTOR_TABLE"):
        FT.FactorTable()
    monkeypatch.setenv("CTF_FACTOR_TABLE", str(tmp_path))            # a folder is not the table
    with pytest.raises(FileNotFoundError, match="CTF_FACTOR_TABLE"):
        paths.factor_table_path()


def test_realdata_default_location(no_table_env, monkeypatch, tmp_path):
    root = tmp_path / "realdata"
    (root / "factor-table").mkdir(parents=True)
    monkeypatch.setenv("CTF_REALDATA", str(root))
    assert paths.factor_table_path() is None                         # folder without the file
    FT.build(root / "factor-table" / "factors.sqlite", [_dump(tmp_path, ["15 = 3 * 5"])])
    assert paths.factor_table_path() == (root / "factor-table" / "factors.sqlite").resolve()
    with FT.FactorTable() as t:
        assert t.lookup(15) is not None


def test_explicit_table_argument_must_exist(tmp_path):
    with pytest.raises(FT.TableMissing, match="nope.sqlite"):
        FT.FactorTable(tmp_path / "nope.sqlite")


# ---- CLI ------------------------------------------------------------------------------------------------

def test_cli_build_lookup_status_and_exit_codes(no_table_env, tmp_path, capsys):
    rng = random.Random(99)
    p, q = _prime(rng, 64), _prime(rng, 64)
    src = _dump(tmp_path, [f"{p * q} = {p} * {q}", "16 = 3 * 5"])
    out = tmp_path / "t.sqlite"
    assert FT.main(["build", str(out), str(src)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["added"] == 1 and rep["rejected"] == 1

    assert FT.main(["lookup", str(p * q), "--table", str(out)]) == 0
    got = json.loads(capsys.readouterr().out)
    assert got["found"] and got["verified"] and got["factors"] == [str(min(p, q)), str(max(p, q))]

    assert FT.main(["lookup", hex(p * q + 2), "--table", str(out)]) == 1
    assert json.loads(capsys.readouterr().out)["found"] is False

    assert FT.main(["status", "--table", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["rows"] == 1

    assert FT.main(["lookup", "15"]) == 3                             # no table configured
    assert "CTF_FACTOR_TABLE" in capsys.readouterr().err
    assert FT.main(["lookup", "--table", str(out)]) == 2               # neither N nor --pem
    assert "exactly one" in capsys.readouterr().err


def test_cli_lookup_from_a_public_key_pem(tmp_path, capsys):
    from Crypto.PublicKey import RSA
    rng = random.Random(5)
    while True:
        p, q = _prime(rng, 256), _prime(rng, 256)
        if (p - 1) % 65537 and (q - 1) % 65537:
            break
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, [f"{p * q} = {p} * {q}"])])
    pem = tmp_path / "pub.pem"
    pem.write_bytes(RSA.construct((p * q, 65537)).export_key())
    assert FT.main(["lookup", "--pem", str(pem), "--table", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["factors"] == [str(min(p, q)), str(max(p, q))]


def test_cli_corrupt_table_exit_code(tmp_path, capsys):
    out = tmp_path / "t.sqlite"
    FT.build(out, [_dump(tmp_path, ["15 = 3 * 5"])])
    db = sqlite3.connect(out)
    db.execute("UPDATE factors SET factors='3,7'")
    db.commit()
    db.close()
    assert FT.main(["lookup", "15", "--table", str(out)]) == 4
    assert "corrupt" in capsys.readouterr().err


# ---- the real table (outside the repo) ---------------------------------------------------------------------

@pytest.mark.needs_realdata("factor-table")
def test_real_factor_table_loads_and_its_rows_verify(monkeypatch):
    for name in ("CTF_FACTOR_TABLE", *env.legacy_names("CTF_FACTOR_TABLE")):
        monkeypatch.delenv(name, raising=False)
    path = paths.factor_table_path()
    assert path is not None, "realdata has factor-table/ but no factors.sqlite in it"
    with FT.FactorTable(path) as t:
        st = t.status()
        assert st["rows"] > 0
        sample = [int(h, 16) for (h,) in t._db.execute("SELECT n FROM factors ORDER BY RANDOM() LIMIT 50")]
        for n in sample:
            assert t.lookup(n) is not None                     # lookup re-verifies the product
