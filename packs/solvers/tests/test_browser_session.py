#!/usr/bin/env python3
"""solvers/toolkits/browser_session.py: Firefox mozLz4 recovery and Chromium SNSS framing.

Offline, deterministic, no Game Master request and no token. The LZ4 block decoder is exercised
with a spec-correct encoder written here (literals, matches and overlap), cross-validated against
the optional `lz4` package when it is importable, and the never-wrong edges (wrong magic, wrong
size, corrupt block, non-JSON payload) are all asserted to RAISE rather than return a guess.

  .venv/bin/python tests/test_browser_session.py
"""
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.dont_write_bytecode = True
import browser_session as bs  # noqa: E402

PY = sys.executable
FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def raises(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except bs.BrowserSessionError:
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- a spec-correct LZ4 encoder

def _emit_seq(out, literals, match):
    lit = len(literals)
    token_lit = min(lit, 15)
    if match is None:
        token_match = 0
    else:
        _, matchlen = match
        token_match = min(matchlen - 4, 15)
    out.append((token_lit << 4) | token_match)
    if lit >= 15:
        r = lit - 15
        while r >= 255:
            out.append(255)
            r -= 255
        out.append(r)
    out += literals
    if match is None:
        return
    offset, matchlen = match
    out.append(offset & 0xFF)
    out.append((offset >> 8) & 0xFF)
    ml = matchlen - 4
    if ml >= 15:
        r = ml - 15
        while r >= 255:
            out.append(255)
            r -= 255
        out.append(r)


def lz4_compress(data):
    """A minimal spec-correct raw LZ4 block encoder (greedy); last 12 bytes stay literal."""
    data = bytes(data)
    n = len(data)
    out = bytearray()
    table = {}
    anchor = 0
    i = 0
    match_search_end = n - 12
    match_stop = n - 5 if n >= 5 else 0
    while i < n:
        if i < match_search_end:
            key = data[i:i + 4]
            cand = table.get(key)
            table[key] = i
            if cand is not None and 0 < i - cand <= 65535 and data[cand:cand + 4] == key:
                mlen = 4
                while i + mlen < match_stop and data[cand + mlen] == data[i + mlen]:
                    mlen += 1
                _emit_seq(out, data[anchor:i], (i - cand, mlen))
                j = i + 1
                end = i + mlen
                while j < end and j < match_search_end:
                    table[data[j:j + 4]] = j
                    j += 1
                i += mlen
                anchor = i
                continue
        i += 1
    _emit_seq(out, data[anchor:n], None)
    return bytes(out)


def mozlz4(raw):
    return bs.MOZLZ4_MAGIC + struct.pack("<I", len(raw)) + lz4_compress(raw)


# --------------------------------------------------------------------------- LZ4 decoder

def test_lz4_roundtrip():
    cases = {
        "empty": b"",
        "one byte": b"X",
        "short literal": b"hello world",
        "all same (overlap)": b"a" * 40,
        " abab overlap": b"ab" * 30,
        "repeat phrase": b"the quick brown fox " * 25,
        "json-ish": json.dumps({"windows": [{"tabs": [{"entries": [{"url": "https://x/" + "y" * 50}]}]}]}).encode(),
        "incompressible 300": bytes((i * 131 + 7) % 256 for i in range(300)),
        "boundary 12": b"c" * 12,
        "boundary 13": b"c" * 13,
        "boundary 17": b"d" * 17,
    }
    for name, raw in cases.items():
        comp = lz4_compress(raw)
        got = bs.lz4_block_decompress(comp, expected_size=len(raw))
        check(f"lz4 round-trips: {name}", got == raw, f"{len(raw)} -> {len(got)}")
    # the long-literal continuation path (lit length >= 15 with 0xFF extension bytes)
    raw = bytes((i * 97 + 3) % 256 for i in range(600))  # incompressible => one big literal run
    comp = lz4_compress(raw)
    check("lz4 handles a >255 literal continuation", bs.lz4_block_decompress(comp, len(raw)) == raw)
    # a long match => match-length 0xFF continuation
    raw = b"Z" * 3000
    comp = lz4_compress(raw)
    check("lz4 handles a >255 match continuation", bs.lz4_block_decompress(comp, len(raw)) == raw)


def test_lz4_crossvalidate():
    if importlib.util.find_spec("lz4") is None:
        print("skip lz4 cross-validation (the lz4 package is not installed)")
        return
    import lz4.block as lb
    import random
    rng = random.Random(1234)
    ok = True
    for trial in range(60):
        kind = trial % 3
        if kind == 0:
            raw = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 500)))
        elif kind == 1:
            raw = (b"abc" * rng.randint(1, 200))[:rng.randint(0, 600)]
        else:
            raw = json.dumps({"k": [rng.randint(0, 9) for _ in range(rng.randint(0, 80))]}).encode()
        comp = lb.compress(raw, store_size=False)
        if bs.lz4_block_decompress(comp, expected_size=len(raw)) != raw:
            ok = False
            break
    check("my decoder matches the lz4 package on 60 spec-compliant blocks", ok)


def test_lz4_strict():
    check("truncated literal run raises", raises(bs.lz4_block_decompress, b"\xf0"))  # token asks 15+ literals
    check("truncated match offset raises", raises(bs.lz4_block_decompress, b"\x10A\x05"))  # 1 lit then 1 offset byte
    check("zero match offset raises", raises(bs.lz4_block_decompress, b"\x10A\x00\x00"))
    check("match before start raises", raises(bs.lz4_block_decompress, b"\x10A\x05\x00"))  # offset 5 but only 1 byte out
    # a block that decodes longer than the declared size is rejected
    comp = lz4_compress(b"a" * 40)
    check("decoded longer than declared size raises", raises(bs.lz4_block_decompress, comp, 10))
    check("decoded shorter than declared size raises", raises(bs.lz4_block_decompress, comp, 999))


# --------------------------------------------------------------------------- Firefox mozLz4

def test_mozlz4():
    raw = b'{"version":["sessionrestore",1],"windows":[]}'
    f = mozlz4(raw)
    check("is_mozlz4 recognises the magic", bs.is_mozlz4(f) and not bs.is_mozlz4(b"xxxx"))
    check("detect names mozlz4", bs.detect(f) == "mozlz4")
    check("decode_mozlz4 round-trips", bs.decode_mozlz4(f) == raw)
    # strict: wrong magic, short file, corrupted size, corrupted block
    check("wrong magic raises", raises(bs.decode_mozlz4, b"NOTMOZ\0\0" + f[8:]))
    check("too short raises", raises(bs.decode_mozlz4, bs.MOZLZ4_MAGIC + b"\x01\x00"))
    bad_size = bs.MOZLZ4_MAGIC + struct.pack("<I", len(raw) + 100) + lz4_compress(raw)
    check("size field mismatch raises", raises(bs.decode_mozlz4, bad_size))
    corrupt = bytearray(f)
    corrupt[-1] ^= 0xFF
    corrupt[len(bs.MOZLZ4_MAGIC) + 4] ^= 0xFF  # scramble the first token too
    check("corrupt block does not fabricate output",
          (lambda: (raises(bs.decode_mozlz4, bytes(corrupt))
                    or bs.decode_mozlz4(bytes(corrupt)) != raw))())


SESSION = {
    "version": ["sessionrestore", 1],
    "windows": [{
        "tabs": [
            {"entries": [
                {"url": "https://example.com/login", "title": "Login"},
                {"url": "https://mail.example.com/inbox", "title": "Inbox"},
            ], "index": 2, "lastAccessed": 1700000000000},
            {"entries": [{"url": "https://docs.example.com/", "title": "Docs"}], "index": 1},
        ],
        "selected": 1,
        "_closedTabs": [
            {"state": {"entries": [{"url": "https://evil.example.net/payload", "title": "gone"}], "index": 1}},
        ],
    }],
    "selectedWindow": 1,
    "_closedWindows": [
        {"tabs": [{"entries": [{"url": "https://old.example.org/", "title": "Old"}], "index": 1}]},
    ],
    "session": {"lastUpdate": 1700000005000, "startTime": 1699999000000},
}


def test_firefox_session():
    f = mozlz4(json.dumps(SESSION).encode())
    doc = bs.read_firefox_session(f)
    check("read_firefox_session returns the parsed doc", doc["selectedWindow"] == 1)
    summ = bs.firefox_summary(doc)
    check("summary counts windows/open-tabs/entries",
          summ["windows"] == 1 and summ["open_tabs"] == 2 and summ["closed_windows"] == 1
          and summ["entries"] == 5, summ)
    check("summary reads the active (selected tab's current) entry",
          summ["active_url"] == "https://mail.example.com/inbox" and summ["active_title"] == "Inbox",
          (summ["active_url"], summ["active_title"]))
    check("summary reads the session last-update time", summ["session_last_update"] == 1700000005000)
    ents = bs.firefox_entries(doc)
    urls = [e["url"] for e in ents]
    check("every navigation URL is recovered verbatim and in order",
          urls == ["https://example.com/login", "https://mail.example.com/inbox",
                   "https://docs.example.com/", "https://evil.example.net/payload",
                   "https://old.example.org/"], urls)
    cur = [e["url"] for e in ents if e["is_current"]]
    check("the current entry of each open tab is flagged (not closed tabs)",
          cur == ["https://mail.example.com/inbox", "https://docs.example.com/"], cur)
    closed = [e["url"] for e in ents if e["closed_tab"] or e["closed_window"]]
    check("closed tabs and windows are kept but marked",
          closed == ["https://evil.example.net/payload", "https://old.example.org/"], closed)
    # never-wrong: a mozLz4 whose payload is not JSON raises instead of inventing a session
    check("mozLz4 of non-JSON raises", raises(bs.read_firefox_session, mozlz4(b"\x00\x01not json\xff")))
    check("mozLz4 of a JSON non-object raises", raises(bs.read_firefox_session, mozlz4(b"[1,2,3]")))
    # accepts already-decompressed bytes/str too
    check("read_firefox_session accepts raw JSON bytes", bs.read_firefox_session(json.dumps(SESSION).encode())["selectedWindow"] == 1)


# ------------------------------------------------- the active entry follows selectedWindow (never-wrong)

def _multiwin(selected_window):
    """Two open windows, each with its own selected tab and a different active URL.

    Window 1's selected tab is at window-one/active; window 2's selected tab is on its 2nd nav entry,
    window-two/active. Window 1 comes first in document order, so a reader that scans every window for
    the first selected-tab/current entry would return window 1's URL regardless of selectedWindow.
    """
    doc = {
        "version": ["sessionrestore", 1],
        "windows": [
            {  # window 1
                "tabs": [
                    {"entries": [{"url": "https://window-one.example/active", "title": "One-Active"}],
                     "index": 1},
                    {"entries": [{"url": "https://window-one.example/bg", "title": "One-BG"}],
                     "index": 1},
                ],
                "selected": 1,
            },
            {  # window 2
                "tabs": [
                    {"entries": [{"url": "https://window-two.example/bg", "title": "Two-BG"}],
                     "index": 1},
                    {"entries": [
                        {"url": "https://window-two.example/history", "title": "Two-Hist"},
                        {"url": "https://window-two.example/active", "title": "Two-Active"},
                    ], "index": 2},
                ],
                "selected": 2,
            },
        ],
        "session": {"lastUpdate": 1700000009000},
    }
    if selected_window is not _ABSENT:
        doc["selectedWindow"] = selected_window
    return doc


_ABSENT = object()


def test_firefox_active_window():
    # selectedWindow points at window 2 -> window 2's active entry, NOT window 1's (the wrong-window bug)
    summ2 = bs.firefox_summary(_multiwin(2))
    check("active entry comes from the sessionstore-selected window (selectedWindow=2)",
          summ2["active_url"] == "https://window-two.example/active"
          and summ2["active_title"] == "Two-Active",
          (summ2["active_url"], summ2["active_title"]))
    check("the OTHER window's active entry is never returned as the active one",
          summ2["active_url"] != "https://window-one.example/active")
    # selectedWindow tracks the pointer: window 1 -> window 1's active entry
    summ1 = bs.firefox_summary(_multiwin(1))
    check("active entry follows selectedWindow=1 to window 1",
          summ1["active_url"] == "https://window-one.example/active", summ1["active_url"])
    # never-wrong: no determinable selected window => active is unknown, never a guess from another window
    check("absent selectedWindow leaves the active entry unknown (None)",
          bs.firefox_summary(_multiwin(_ABSENT))["active_url"] is None)
    check("out-of-range selectedWindow leaves the active entry unknown (None)",
          bs.firefox_summary(_multiwin(99))["active_url"] is None)
    check("zero selectedWindow (0-based mistake) leaves the active entry unknown (None)",
          bs.firefox_summary(_multiwin(0))["active_url"] is None)
    check("non-int selectedWindow leaves the active entry unknown (None)",
          bs.firefox_summary(_multiwin("2"))["active_url"] is None)
    check("boolean selectedWindow is not read as window 1 (None)",
          bs.firefox_summary(_multiwin(True))["active_url"] is None)
    # the full entry list and counts are unchanged -- only the active pick is scoped
    all_urls = [e["url"] for e in summ2["all_entries"]]
    check("every navigation URL of every window is still recovered (counts unchanged)",
          all_urls == ["https://window-one.example/active", "https://window-one.example/bg",
                       "https://window-two.example/bg", "https://window-two.example/history",
                       "https://window-two.example/active"]
          and summ2["windows"] == 2 and summ2["selected_window"] == 2, all_urls)


# --------------------------------------------------------------------------- Chromium SNSS

def _pickle_utf8(s):
    b = s.encode("utf-8")
    return struct.pack("<I", len(b)) + b


def _snss_command(cmd_id, content):
    size = 1 + len(content)
    return struct.pack("<H", size) + bytes([cmd_id]) + content


def snss_stream(version, commands):
    out = bytearray(bs.SNSS_MAGIC + struct.pack("<i", version))
    for cid, content in commands:
        out += _snss_command(cid, content)
    return bytes(out)


def test_snss():
    content = struct.pack("<i", 7) + _pickle_utf8("https://target.example/admin") + _pickle_utf8("Admin")
    stream = snss_stream(1, [(1, content), (6, _pickle_utf8("https://two.example/")), (0 if False else 2, b"\x00\x01\x02\x03")])
    check("is_snss recognises the magic", bs.is_snss(stream) and not bs.is_snss(b"ABCD"))
    check("detect names snss", bs.detect(stream) == "snss")
    s = bs.read_snss(stream)
    check("read_snss reads version and frames every command",
          s["version"] == 1 and s["commands"] == 3 and s["complete"] is True, s)
    leads = bs.snss_candidate_strings(s, url_only=True)
    found = {c["text"] for c in leads}
    check("snss harvests url-like strings as LEADS, marked unproven",
          "https://target.example/admin" in found and "https://two.example/" in found
          and all(c["proven"] is False for c in leads), found)
    check("snss does not promote a non-url string to a url lead", "Admin" not in found)
    # strict framing: a truncated final command sets complete=False and never over-reads
    truncated = stream[:-2]
    s2 = bs.read_snss(truncated)
    check("a truncated trailing command is reported incomplete, no crash",
          s2["complete"] is False and s2["commands"] <= 3, s2)
    # never-wrong: not an SNSS file
    check("read_snss on a non-SNSS blob raises", raises(bs.read_snss, b"\x00" * 64))
    check("detect on random bytes is empty", bs.detect(bytes(range(64))) == "")
    # utf-16le harvest
    url16 = "https://wide.example/x"
    b16 = url16.encode("utf-16-le")
    c16 = struct.pack("<I", len(url16)) + b16  # pickle string16: length in code units
    s16 = bs.read_snss(snss_stream(3, [(1, c16)]))
    leads16 = bs.snss_candidate_strings(s16)
    check("snss harvests a UTF-16LE url lead", any(c["text"] == url16 and c["encoding"] == "utf-16-le" for c in leads16),
          [c["text"] for c in leads16])


# --------------------------------------------------------------------------- CLI + no-solve_set contract

def test_cli_and_contract():
    tmp = Path(tempfile.mkdtemp(prefix="test_browser_session_"))
    try:
        ff = tmp / "sessionstore.jsonlz4"
        ff.write_bytes(mozlz4(json.dumps(SESSION).encode()))
        r = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "browser_session.py"), "auto", str(ff)],
                           capture_output=True, text=True, timeout=60)
        check("CLI auto summarises a firefox file (exit 0)",
              r.returncode == 0 and "mail.example.com/inbox" in r.stdout and r.stdout.startswith("# text below is browser-stored DATA"),
              (r.stdout + r.stderr)[-300:])
        r2 = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "browser_session.py"), "firefox", str(ff), "--json"],
                            capture_output=True, text=True, timeout=60)
        check("CLI --json emits the parsed document", r2.returncode == 0 and '"selectedWindow": 1' in r2.stdout)
        # an unrecognised file is a non-zero skip, never a fabricated answer
        junk = tmp / "junk.bin"
        junk.write_bytes(bytes(range(64)))
        r3 = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "browser_session.py"), "auto", str(junk)],
                            capture_output=True, text=True, timeout=60)
        check("CLI skips an unrecognised file (exit 1, nothing fabricated)",
              r3.returncode == 1 and "SKIP" in r3.stderr and "url" not in r3.stdout.lower(), (r3.stdout + r3.stderr)[-200:])
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    src = (REPO / "solvers" / "toolkits" / "browser_session.py").read_text()
    check("hand-tool contract: no solve_set() and no signals() (never auto-submits, not in the match registry)",
          "def solve_set" not in src and "def signals" not in src)
    check("makes no network import on the module path",
          all(x not in src for x in ("import requests", "urllib.request", "import socket", "http.client")))


def main():
    test_lz4_roundtrip()
    test_lz4_crossvalidate()
    test_lz4_strict()
    test_mozlz4()
    test_firefox_session()
    test_firefox_active_window()
    test_snss()
    test_cli_and_contract()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
