"""flagscan: offline "find the flag row" scanner over SQLite / CSV / SQL-dump fixtures."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))
import flagscan  # noqa: E402


def _make_sqlite(path, flag="CSCTF{l1te_sql_r0w}"):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    rows = [(i, f"user{i}", f"pw{i}pad") for i in range(1, 100)]
    rows[19] = (20, "winner", flag)          # the flag row, like CSCTF 2024 Lite (id 20)
    con.executemany("INSERT INTO users VALUES (?,?,?)", rows)
    con.commit()
    con.close()


def test_scan_sqlite_finds_flag_row(tmp_path):
    db = tmp_path / "mydatabase.db"
    _make_sqlite(str(db))
    hits = flagscan.scan_path(str(db))
    assert len(hits) == 1
    h = hits[0]
    assert h.table == "users"
    assert h.rowid == 20
    assert h.column == "password"
    assert flagscan.flags(hits) == ["CSCTF{l1te_sql_r0w}"]


def test_scan_csv_finds_flag(tmp_path):
    c = tmp_path / "data.csv"
    c.write_text(
        "id,user,secret\n"
        "1,alice,nothing1\n"
        "2,bob,CSCTF{csv_flag_here}\n"
        "3,carol,nothing3\n"
    )
    hits = flagscan.scan_path(str(c))
    assert flagscan.flags(hits) == ["CSCTF{csv_flag_here}"]
    assert hits[0].column == "secret"


def test_scan_sql_dump(tmp_path):
    # the Database archetype: a MySQL dump, no server needed -- regex pass over the text
    s = tmp_path / "dump.sql"
    s.write_text(
        "INSERT INTO `users` VALUES (1,'faker','xxxx');\n"
        "INSERT INTO `users` VALUES (2,'faker2','yyyy');\n"
        "INSERT INTO `users` VALUES (500,'target','CSCTF{mysql_dump_flag}');\n"
    )
    hits = flagscan.scan_path(str(s))
    assert flagscan.flags(hits) == ["CSCTF{mysql_dump_flag}"]


def test_custom_pattern_substring(tmp_path):
    c = tmp_path / "d.csv"
    c.write_text("a,b\n1,needle_here\n2,haystack\n")
    hits = flagscan.scan_path(str(c), pattern="needle")
    assert len(hits) == 1
    assert "needle" in hits[0].value


def test_custom_pattern_regex(tmp_path):
    c = tmp_path / "d.csv"
    c.write_text("a,b\n1,abc123\n2,zzz\n")
    hits = flagscan.scan_path(str(c), pattern=r"[a-z]{3}\d{3}", regex=True)
    assert len(hits) == 1
    assert hits[0].value == "abc123"


def test_no_flag_returns_empty_flags(tmp_path):
    db = tmp_path / "clean.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE t (x TEXT)")
    con.executemany("INSERT INTO t VALUES (?)", [("ordinary",), ("rows",)])
    con.commit()
    con.close()
    hits = flagscan.scan_path(str(db))
    assert hits == []
    assert flagscan.flags(hits) == []


def test_report_renders_flag(tmp_path):
    db = tmp_path / "m.db"
    _make_sqlite(str(db), flag="CSCTF{rep0rt}")
    out = flagscan.report([str(db)])
    assert "CSCTF{rep0rt}" in out
    assert "FLAG candidate" in out
