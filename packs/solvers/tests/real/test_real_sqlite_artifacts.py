#!/usr/bin/env python3
"""`sqlite_artifacts` on real artifacts (the cache of tests/real/fetch_b.py; SKIPs without it).

  .venv/bin/python tests/real/test_real_sqlite_artifacts.py

Offline, nothing written to the cache, no request. Expected values are queried here with `sqlite3`
(read-only), or are stated by the source (a write-up's flag, a data set's own name).

- Huntress CTF 2024 "Ancient Fossil": the flag of the write-up, end to end.
- plaso's test profiles: Chrome History of 2011 and of version 59, two cookie stores, Web Data,
  Firefox places and cookies, Safari History.db, an iMessage chat.db, quarantine events, a WAL pair.
- dfindexeddb's LevelDB folders ("100k keys delete": 100,000 puts and 10 deletes by its name).
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("sqlite_artifacts")
P = "sqlite_artifacts/plaso/"
FLAG = "flag{2ed33f365669ea9f10b1a4ea4566fe8c}"         # the write-up's answer (fossil export | grep flag)


def sql(rel, query):
    con = sqlite3.connect(f"file:{rd.CACHE / rel}?mode=ro", uri=True)
    try:
        return con.execute(query).fetchall()
    finally:
        con.close()


def ask_all(S, fs, questions):
    return S.solve_set([{"qid": f"q{i}", "question": t} for i, t in enumerate(questions)], fs, {})


def main() -> int:
    S = rd.toolkit("sqlite_artifacts")
    f = "sqlite_artifacts/ctf2024_ancient_fossil/ancient.fossil"
    if R.need("Ancient Fossil", f):
        fs = rd.files(f)
        ev = R.timed("fossil: Evidence of a 624 KiB repository", lambda: S.Evidence(fs))
        db = next(iter(ev.dbs.values()))
        blobs = R.timed("fossil: every artifact, deltas applied", lambda: S.fossil_blobs(db))
        R.check("fossil: recognised by its schema; every blob row is readable",
                list(ev.kinds.values()) == ["fossil_repository"] and len(blobs) == sql(f, "select count(*) from blob")[0][0] == 604, len(blobs))
        note = S.fossil_notable(blobs)
        R.check("fossil: the flag is the one flag-like content and the odd one out among 201 files",
                [t for _, t in note["flags"]] == [FLAG] and [r[0] for r in note["odd"]] == [note["flags"][0][0]] and note["files"] == 201, note)
        R.check("fossil: the triage names it (it printed the first artifacts only)", f"FLAG-LIKE in rid {note['flags'][0][0]}: {FLAG}" in S.report(fs))
        ans = ask_all(S, fs, ["What is the flag?", "What is the check-in comment of the first commit?", "How many check-ins are there?"])
        R.check("fossil: 'what is the flag' is a one-option pick holding the write-up's flag (never plain)", rd.options(ans["q0"]) == [FLAG], ans["q0"])
        first = sql(f, "select coalesce(ecomment, comment) from event where type='ci' order by mtime limit 1")[0][0]
        R.check("fossil: the first check-in's comment", ans["q1"] == first, (ans["q1"], first))
        R.check("fossil: a count it does not model is None", ans["q2"] is None, ans["q2"])
    h = P + "chrome/History"
    if R.need("Chrome History (2011)", h):
        fs = rd.files(h)
        d = sql(h, "select full_path, url, total_bytes, start_time from downloads order by id")
        top = sql(h, "select url, title, visit_count from urls order by visit_count desc limit 2")
        ans = R.timed("chrome 2011: solve_set of 9 questions", lambda: ask_all(S, fs, [
            "How many downloads are in the history?", "What URL was funcats_scr.exe downloaded from?", "What is the size of the download funcats_scr.exe?",
            "What is the title of the most visited page?", "How many times was http://start.ubuntu.com/10.04/Google/ visited?",
            "What file was downloaded from fatloss4idiotsx.com?", "When was funcats_scr.exe downloaded?", "How many URLs are in the browser history?",
            "What was the last URL visited?"]))
        # plain when the carve of deleted rows finished; a one-option pick when its 0.6 s wall-clock budget
        # ran out on a loaded machine (this check failed once in the review for that reason)
        R.check("chrome 2011: downloads", str(len(d)) == "2" and (ans["q0"] == "2" or rd.options(ans["q0"]) == ["2"]), ans["q0"])
        R.check("chrome 2011: a download's URL and size", (ans["q1"], ans["q2"]) == (d[0][1], str(d[0][2])), (ans["q1"], ans["q2"]))
        R.check("chrome 2011: the most visited page (strictly the most)", ans["q3"] == top[0][1] and top[0][2] > top[1][2], ans["q3"])
        R.check("chrome 2011: a URL's visit count", ans["q4"] == str(top[0][2]) == "4", ans["q4"])
        R.check("chrome 2011: 'what file was downloaded from <site>' offers the file, not the URL (was the URL, plain)",
                sorted(rd.options(ans["q5"])) == sorted([d[0][0], d[0][0].rsplit("/", 1)[-1]]), ans["q5"])
        R.check("chrome 2011: the old downloads table keeps Unix seconds: 2011-05-23, not January 1601",
                "2011-05-23T08:35:30Z" in rd.options(ans["q6"]) and not any(str(v).startswith("1601") for v in rd.options(ans["q6"])) and d[0][3] == 1306139730, ans["q6"])
        n_urls, n_visits = sql(h, "select count(*) from urls")[0][0], sql(h, "select count(*) from visits")[0][0]
        R.check("chrome 2011: 'how many URLs' is unsure between url rows and visit rows", {str(n_urls), str(n_visits)} <= set(rd.options(ans["q7"])), ans["q7"])
        R.check("chrome 2011: the last URL visited", ans["q8"] == sql(h, "select url from urls order by last_visit_time desc limit 1")[0][0], ans["q8"])
    h59 = P + "chrome/History-59.0.3071.86"
    if R.need("Chrome History 59", h59):
        d = sql(h59, "select target_path, total_bytes, mime_type from downloads")[0]
        chain = [r[0] for r in sql(h59, "select url from downloads_url_chains order by chain_index")]
        ans = ask_all(S, rd.files(h59), ["What URL was the file downloaded from?", "What is the name of the downloaded file?", "What is the MIME type of the download?",
                                        "What is the size of the downloaded file?"])
        R.check("chrome 59: the download's one chain URL", ans["q0"] == chain[0] and len(chain) == 1, ans["q0"])
        R.check("chrome 59: file name or path, unsure", sorted(rd.options(ans["q1"])) == sorted([d[0], d[0].rsplit("/", 1)[-1]]), ans["q1"])
        R.check("chrome 59: mime and size", (ans["q2"], ans["q3"]) == (d[2], str(d[1])), (ans["q2"], ans["q3"]))
    for rel, table, col in ((P + "chrome/Cookies-68.0.3440.106", "cookies", "host_key"), (P + "chrome/cookies.db", "cookies", "host_key"),
                            (P + "firefox/firefox_10_cookies.sqlite", "moz_cookies", "host")):
        if R.need(rel.rsplit("/", 1)[-1], rel):
            n = sql(rel, f"select count(*) from {table}")[0][0]
            a = rd.ask(S, rd.files(rel), "How many cookies are stored?")       # a pick of that one number when the carve's budget ran out (load)
            R.check(f"{rel.rsplit('/', 1)[-1]}: cookies stored = rows of {table}", a == str(n) or rd.options(a) == [str(n)], (a, n))
    c = P + "chrome/cookies.db"
    if R.need("cookies.db", c):
        row = sql(c, "select host_key, value from cookies where name='leo_auth_token'")
        ans = ask_all(S, rd.files(c), ["What is the value of the cookie leo_auth_token?", "Which host set the cookie leo_auth_token?"])
        R.check("cookies.db: a named cookie's value and host", len(row) == 1 and (ans["q1"], ans["q0"]) == row[0], ans)
    c68 = P + "chrome/Cookies-68.0.3440.106"
    if R.need("Cookies 68", c68):
        ans = ask_all(S, rd.files(c68), ["What is the value of the cookie guest_id?", "What is the name of the cookie set by .fbi.gov?"])
        R.check("Cookies 68: an encrypted value with no key in the delivery is None", ans["q0"] is None, ans["q0"])
        R.check("Cookies 68: a host's one cookie", [(ans["q1"],)] == sql(c68, "select name from cookies where host_key='.fbi.gov'"), ans["q1"])
    s = P + "safari/History.db"
    if R.need("Safari History.db", s):
        first = sql(s, "select i.url from history_items i join history_visits v on v.history_item=i.id order by v.visit_time limit 1")[0][0]
        R.check("safari: the first URL visited", rd.ask(S, rd.files(s), "What was the first URL visited?") == first, first)
    m = P + "sqlite/imessage_chat.db"
    if R.need("iMessage chat.db", m):
        rows = sql(m, "select m.text, m.is_from_me, h.id from message m left join handle h on h.ROWID=m.handle_id order by m.date")
        ans = ask_all(S, rd.files(m), ["Who sent the first message?", "What is the text of the last message?"])
        R.check("imessage: the sender of the first (received) message", rows[0][1] == 0 and ans["q0"] == rows[0][2], (ans["q0"], rows[0][1:]))
        R.check("imessage: the last message's text", ans["q1"] == rows[-1][0], (ans["q1"], rows[-1][0]))
    q = P + "sqlite/quarantine.db"
    if R.need("quarantine events", q):
        n = sql(q, "select count(*) from LSQuarantineEvent")[0][0]
        url = sql(q, "select LSQuarantineDataURLString from LSQuarantineEvent where LSQuarantineDataURLString like '%googlechrome.dmg'")
        ans = ask_all(S, rd.files(q), ["How many downloads are there?", "What URL was googlechrome.dmg downloaded from?"])
        R.check("quarantine: the live rows are offered; rows found in free space keep the count unsure", str(n) in rd.options(ans["q0"]) or ans["q0"] == str(n), ans["q0"])
        R.check("quarantine: a download's URL", len(url) == 1 and ans["q1"] == url[0][0], ans["q1"])
    w = (P + "wal_database.db", P + "wal_database.db-wal")
    if R.need("WAL pair", *w):
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="huntress-real-b-wal-"))
        for rel in w:
            shutil.copy(rd.CACHE / rel, tmp / Path(rel).name)
        con = sqlite3.connect(tmp / "wal_database.db")
        want = con.execute("select count(*) from MyTable").fetchone()[0]
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)
        db = next(iter(S.Evidence(rd.files(*w)).dbs.values()))
        R.check("wal: the live view through the -wal equals sqlite3's own (11 rows)", len(db.tables.get("MyTable", [])) == want == 11, (len(db.tables.get("MyTable", [])), want))
    ld = "sqlite_artifacts/dfindexeddb/leveldb/100k keys delete/"
    if R.need("LevelDB 100k keys delete", ld + "000004.log", ld + "000005.ldb"):
        log = R.timed("leveldb: a 705 KiB write-ahead log", lambda: S.leveldb_records(rd.data(ld + "000004.log"), "000004.log"))
        tab = R.timed("leveldb: a 1 MiB table (snappy blocks)", lambda: S.leveldb_records(rd.data(ld + "000005.ldb"), "000005.ldb"))
        dead = sum(1 for r in log + tab if str(r.get("live", r.get("state"))) not in ("live", "True"))
        R.check("leveldb: the table and the log hold the data set's 100,000 puts and 10 deletes", len(log) + len(tab) - dead == 100000 and dead == 10, (len(log), len(tab), dead))
    one = "sqlite_artifacts/dfindexeddb/leveldb/create key/000003.log"
    if R.need("LevelDB create key", one):
        r = S.leveldb_records(rd.data(one), "000003.log")
        R.check("leveldb: the one record of 'create key'", [(x["key"], x["value"]) for x in r] == [("test str", "test value")], r)
    for rel in (P + "firefox/places.sqlite", P + "firefox/places118.sqlite", P + "chrome/Web Data", P + "android/mmssms.db", P + "sqlite/skype_main.db"):
        if R.need(rel.rsplit("/", 1)[-1], rel):
            fs = rd.files(rel)
            ev = R.timed(f"{rel.rsplit('/', 1)[-1]}: Evidence", lambda: S.Evidence(fs))
            db = next(iter(ev.dbs.values()))
            tables = {t: n for t, n in ((r[0], sql(rel, f'select count(*) from "{r[0]}"')[0][0]) for r in sql(rel, "select name from sqlite_master where type='table' and name not like 'sqlite_%'"))
                      if not t.startswith(("words", "fts", "moz_origins_"))}
            mine = {t: len(rows) for t, rows in db.tables.items() if t in tables}
            R.check(f"{rel.rsplit('/', 1)[-1]}: every table's live row count equals sqlite3's", all(mine.get(t) == n for t, n in tables.items() if t in mine) and mine,
                    {t: (mine.get(t), n) for t, n in tables.items() if mine.get(t) != n})
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
