"""speedrun/common.py (ZipView), speedrun/wire.py (FastCTFd) and speedrun/corpus.py (speed gate).

Every fixture is synthetic: zips are built here, and the CTFd is a loopback http.server in this
process. Nothing contacts a platform.
"""
from __future__ import annotations

import io
import json
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import pyzipper  # requirements: pinned in the .venv; a missing one fails the import loudly

from speedrun import common, corpus, wire

TOKEN = "tkn-123abc"


# ---- common: ZipView ----------------------------------------------------------------------------------

def _aes_zip(members: dict, password: bytes) -> bytes:
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password)
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _plain_zip(members: dict, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _store_passwords(root, *values):
    rows = [{"value": v, "added": f"2026-01-0{i + 1}T00:00:00Z", "source": "player"} for i, v in enumerate(values)]
    (root / "_passwords.json").write_text(json.dumps({"passwords": rows}))


def test_zipview_reads_winzip_aes_with_default_password(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    body = b"flag-bytes " * 300
    zv = common.open_zip(_aes_zip({"a/b.txt": body, "c.bin": b"\x00\x01"}, b"infected"))
    assert zv.names() == ["a/b.txt", "c.bin"]
    assert zv.info("a/b.txt") == (len(body), 8, True)
    assert zv.read("a/b.txt") == body
    assert zv.check("a/b.txt")


def test_zipview_falls_back_to_a_stored_password(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    data = _aes_zip({"x.txt": b"secret member"}, b"hunter2")
    with pytest.raises(common.ZipError, match="wrong password"):
        common.open_zip(data).read("x.txt")
    _store_passwords(tmp_path, "nope", "hunter2")
    zv = common.open_zip(data)
    assert zv.read("x.txt") == b"secret member"
    assert zv.password == b"hunter2"


def test_zipview_plain_methods_prefix_shift_and_read_many():
    members = {f"m{i}.txt": (f"member {i} " * 50).encode() for i in range(6)}
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
        data = b"MZ-self-extractor-stub" * 10 + _plain_zip(members, method)   # bytes before the zip
        zv = common.ZipView(data)
        assert zv.names() == list(members)
        got = zv.read_many(list(members))
        assert got == members
        assert all(zv.check(n) for n in members)


def test_no_end_of_central_directory_is_a_named_error():
    with pytest.raises(common.ZipError, match="no end of central directory"):
        common.ZipView(b"not a zip at all")


def test_data_root_follows_env(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_SPEED_DATA", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    assert common.data_root() == tmp_path / "wd"
    monkeypatch.setenv("CTF_SPEED_DATA", str(tmp_path / "speed"))
    assert common.data_root() == tmp_path / "speed"


def test_passwords_order_infected_first_then_newest(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    _store_passwords(tmp_path, "older", "newer", "infected")
    assert common.passwords() == [b"infected", b"newer", b"older"]


# ---- wire: a loopback CTFd ------------------------------------------------------------------------------

class _CTFd:
    def __init__(self, file_delay=0.3, submit_hold=0.05):
        self.file_delay = file_delay
        self.submit_hold = submit_hold
        self.conns = set()
        self.auth = []
        self.paths = []
        self.submits = []          # (t_start, t_end, body)
        self.lock = threading.Lock()
        self.active_submits = 0
        self.max_active_submits = 0
        fx = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def setup(self):
                super().setup()
                with fx.lock:
                    fx.conns.add(self.client_address)

            def _send(self, code, obj=None, raw=None, ctype="application/json"):
                body = raw if raw is not None else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authed(self):
                a = self.headers.get("Authorization")
                with fx.lock:
                    fx.auth.append(a)
                    fx.paths.append(self.path)
                if a != f"Token {TOKEN}":
                    self._send(401, raw=b"<html>login</html>", ctype="text/html")
                    return False
                return True

            def do_GET(self):
                if not self._authed():
                    return
                p = self.path
                if p == "/api/v1/challenges":
                    return self._send(200, {"success": True, "data": [{"id": 1, "name": "one"}, {"id": 2, "name": "two"}]})
                if p.startswith("/api/v1/challenges/"):
                    cid = int(p.rsplit("/", 1)[1])
                    return self._send(200, {"success": True, "data": {
                        "id": cid, "files": [f"/files/aa/f{cid}a.bin?token=QSECRET", f"/files/bb/f{cid}b.bin?token=QSECRET"]}})
                if p.startswith("/files/missing"):
                    return self._send(404, raw=b"nope", ctype="text/plain")
                if p.startswith("/files/"):
                    time.sleep(fx.file_delay)
                    name = p.split("?", 1)[0].rsplit("/", 1)[1]
                    return self._send(200, raw=b"BYTES:" + name.encode(), ctype="application/octet-stream")
                self._send(404, {"success": False})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if not self._authed():
                    return
                if self.path != "/api/v1/challenges/attempt":
                    return self._send(404, {"success": False})
                t0 = time.monotonic()
                with fx.lock:
                    fx.active_submits += 1
                    fx.max_active_submits = max(fx.max_active_submits, fx.active_submits)
                time.sleep(fx.submit_hold)
                with fx.lock:
                    fx.active_submits -= 1
                    fx.submits.append((t0, time.monotonic(), body))
                ok = body.get("submission") == "flag{ok}"
                self._send(200, {"success": True, "data": {"status": "correct" if ok else "incorrect",
                                                           "message": "Correct" if ok else "Incorrect"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ctfd(monkeypatch):
    fx = _CTFd()
    # R-13: the fast wire contacts only the event platform (ctf.scope.check_platform_url); the
    # loopback fixture is the platform for this test through CTF_PLATFORM_URL.
    monkeypatch.setenv("CTF_PLATFORM_URL", fx.url)
    yield fx
    fx.close()


def test_target_rules():
    t = wire.target("https://ctf.example.org/")
    assert (t.host, t.port, t.tls, t.fake, t.prefix) == ("ctf.example.org", 443, True, False, "")
    t = wire.target("https://ctf.example.org:8443/event")
    assert (t.port, t.prefix, t.base) == (8443, "/event", "https://ctf.example.org:8443/event/")
    assert wire.target("http://127.0.0.1:8000/").fake
    for bad in ("http://ctf.example.org/", "ftp://x/", "https://u:p@x/", "https://x/?a=1", ""):
        with pytest.raises(wire.WireError):
            wire.target(bad)


def test_headers_hold_token_but_never_show_it():
    h = wire.Headers(wire.target("https://ctf.example.org/"), TOKEN)
    assert TOKEN not in repr(h)
    assert f"Authorization: Token {TOKEN}\r\n".encode() in h.get("/api/v1/challenges")
    with pytest.raises(wire.WireError) as e:
        wire.Headers(wire.target("https://ctf.example.org/"), "abc\r\nX-Evil: 1")
    assert "abc" not in str(e.value)
    with pytest.raises(wire.WireError):
        h.get("/a b\r\nHost: evil")


def test_open_preconnects_and_reuses_connections(ctfd):
    with wire.FastCTFd(ctfd.url, TOKEN, conns=3, submit_interval_s=0) as c:
        deadline = time.monotonic() + 2
        while len(ctfd.conns) < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(ctfd.conns) == 3 and ctfd.paths == []     # opened, no request spent
        rows = c.list_challenges()
        assert [r["id"] for r in rows] == [1, 2]
        assert c.challenge(2)["id"] == 2
        assert c.list_challenges() == rows
        assert len(ctfd.conns) == 3                          # no new connection for sequential reads
    assert ctfd.auth and set(ctfd.auth) == {f"Token {TOKEN}"}


def test_bad_token_is_a_loud_error(ctfd):
    with wire.FastCTFd(ctfd.url, "wrong-token", conns=1) as c:
        with pytest.raises(wire.FastCTFdError, match="HTTP 401"):
            c.list_challenges()


def test_download_many_runs_in_parallel_and_redacts_queries(ctfd):
    with wire.FastCTFd(ctfd.url, TOKEN, conns=4) as c:
        files = c.challenge(1)["files"] + c.challenge(2)["files"]
        t = time.perf_counter()
        got = c.download_many(files)
        dt = time.perf_counter() - t
        assert got == {f"f{i}{s}.bin": f"BYTES:f{i}{s}.bin".encode() for i in (1, 2) for s in "ab"}
        assert dt < 4 * ctfd.file_delay * 0.6, dt      # serial would take 4 x file_delay
        with pytest.raises(wire.FastCTFdError) as e:
            c.download_many(["/files/missing/x.bin?token=QSECRET"])
        assert "HTTP 404" in str(e.value) and "QSECRET" not in str(e.value)


def test_detail_of_several_challenges_in_parallel(ctfd):
    with wire.FastCTFd(ctfd.url, TOKEN, conns=2) as c:
        got = c.challenges([1, 2, 1])
    assert sorted(got) == [1, 2] and got[2]["id"] == 2


def test_off_host_file_url_and_hint_paths_are_refused(ctfd):
    c = wire.FastCTFd(ctfd.url, TOKEN, conns=1)
    for url in ("https://evil.example/files/x", "//evil.example/files/x", "http://127.0.0.1:1/files/x"):
        with pytest.raises(wire.WireError, match="refused|bad"):
            c.file_path(url)
    assert c.file_path(ctfd.url + "files/x?token=1") == "/files/x?token=1"
    for p in ("/unlocks", "/hints/7"):
        with pytest.raises(wire.WireError, match="paid hint"):
            c.api_path(p)
    assert c.api_path("/hints") == "/api/v1/hints"


def test_not_open_is_a_named_error(ctfd):
    with pytest.raises(wire.WireError, match="not open"):
        wire.FastCTFd(ctfd.url, TOKEN).list_challenges()


def test_from_config_needs_a_token(monkeypatch):
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://ctf.example.org")   # the platform (R-13 scope guard)
    cfg = SimpleNamespace(base_url="https://ctf.example.org", token=None, cookie="c",
                          request_timeout_s=5.0, submit_interval_min_s=3.0, user_agent="ua")
    with pytest.raises(wire.WireError, match="API token"):
        wire.FastCTFd.from_config(cfg)
    cfg.token = TOKEN
    c = wire.FastCTFd.from_config(cfg)
    assert c.submit_interval_s == 3.0 and c.timeout == 5.0 and TOKEN not in repr(c)


def test_submits_are_serial_and_spaced(ctfd):
    gap = 0.3
    with wire.FastCTFd(ctfd.url, TOKEN, conns=3, submit_interval_s=gap) as c:
        out = {}
        threads = [threading.Thread(target=lambda f=f: out.__setitem__(f, c.submit(1, f)))
                   for f in ("flag{ok}", "flag{no}", "flag{ok}")]
        for th in threads:
            th.start()
        for th in threads:
            th.join(10)
    assert ctfd.max_active_submits == 1
    starts = sorted(s[0] for s in ctfd.submits)
    assert len(starts) == 3
    assert all(b - a >= gap * 0.9 for a, b in zip(starts, starts[1:])), starts
    assert out["flag{ok}"].correct and out["flag{no}"].status == "incorrect"
    assert all(s[2]["challenge_id"] == 1 for s in ctfd.submits)


# ---- corpus: the speed gate ---------------------------------------------------------------------------

def _case(name, lane="crypto", expected=None, args=None):
    return corpus.Case(name, lane, args if args is not None else (name,), expected or {"flag": f"F{{{name}}}"})


class _StepClock:
    """A perf_counter that moves only when a solver says it took time: the gate's arithmetic (each case's
    ms, the lane's median and max) read off exact durations, whatever the machine's load (SH-08)."""

    def __init__(self):
        self.now = 1000.0

    def perf_counter(self):
        return self.now

    def take(self, seconds):
        self.now += seconds


def test_gate_lane_median_and_max(monkeypatch):
    # The gate's timer is corpus.time.perf_counter; a step clock in its place gives every case exactly its
    # stated duration. (With real sleeps a loaded machine stretched the 20 ms median past 40 ms.)
    clock = _StepClock()
    monkeypatch.setattr(corpus, "time", SimpleNamespace(perf_counter=clock.perf_counter))
    delay = {"a": 0.01, "b": 0.02, "c": 0.04, "w": 0.07}

    def solver(name):
        clock.take(delay[name])
        return f"F{{{name}}}"

    s = corpus.run_gate([_case(n) for n in "abc"] + [_case("w", lane="web")], solver).lanes()
    assert s["crypto"]["cases"] == 3 and s["web"]["cases"] == 1
    assert s["crypto"]["median_ms"] == 20.0 and s["crypto"]["max_ms"] == 40.0
    assert s["web"]["median_ms"] == s["web"]["max_ms"] == 70.0      # a lane is its own cases only
    assert s["crypto"]["budget_ms"] is None
    # replay(repeat=3) keeps the best of its timed calls: 30, 10, 50 ms -> 10 ms
    runs = iter((0.03, 0.01, 0.05))
    d = corpus.replay(lambda name: (clock.take(next(runs)), f"F{{{name}}}")[1], _case("r"), repeat=3)
    assert d.exact and round(d.seconds * 1000, 6) == 10.0


def test_gate_times_cases_on_the_real_clock():
    # The real timer: a case never measures less than it slept (a lower bound, which load cannot break).
    def solver(name):
        time.sleep(0.02)
        return f"F{{{name}}}"

    s = corpus.run_gate([_case("a")], solver).lanes()
    assert s["crypto"]["median_ms"] >= 20 and s["crypto"]["max_ms"] >= 20
    assert corpus.run_gate([_case("a")], solver, {"crypto": 10}).rows[0].word == "SLOW"


def test_gate_words_and_failure(monkeypatch):
    # On the step clock (above) only "slow" takes time, so no case but it can come out SLOW because the
    # machine was busy (a real 10 ms budget for the instant cases was a load race; SH-08).
    clock = _StepClock()
    monkeypatch.setattr(corpus, "time", SimpleNamespace(perf_counter=clock.perf_counter))

    def solver(name):
        if name == "boom":
            raise RuntimeError("crashed")
        if name == "wrong":
            return "F{other}"
        if name == "guess":
            g = type("G", (dict,), {})({"flag": "F{x}"})
            g.guessed = {"flag"}
            return g
        if name == "slow":
            clock.take(0.03)
        return f"F{{{name}}}"

    rep = corpus.run_gate([_case("ok"), _case("wrong"), _case("boom"), _case("guess"), _case("slow")],
                          solver, {"crypto": 10})
    words = {r.name: r.word for r in rep.rows}
    assert words == {"ok": "OK", "wrong": "WRONG", "boom": "MISSING", "guess": "GUESS-MISS", "slow": "SLOW"}
    assert not rep.ok
    assert "crashed" in next(r.error for r in rep.rows if r.name == "boom")
    assert corpus.run_gate([_case("ok")], solver, {"crypto": 1000}).ok
    assert corpus.run_gate([_case("slow")], solver, {"crypto": 31}).ok      # 30 ms under a 31 ms budget


def test_gate_with_no_cases_fails_loudly():
    with pytest.raises(corpus.GateError, match="no saved case"):
        corpus.run_gate([], lambda *a: None, skipped=[("x", "no key")])
    with pytest.raises(corpus.GateError):
        corpus.parse_budgets(["crypto"])
    assert corpus.parse_budgets(["Crypto=25"]) == {"crypto": 25.0}


def _workspace(root):
    for d, cat, flag in (("1-alpha", "Crypto", "F{alpha}"), ("2-beta", "Web", "F{beta}"), ("3-gamma", "Web", None)):
        p = root / d
        p.mkdir(parents=True)
        (p / "challenge.json").write_text(json.dumps({"id": int(d[0]), "category": cat}))
        if flag:
            (p / "flag.txt").write_text(flag + "\n")


def test_workspace_cases_and_cli_gate(tmp_path, monkeypatch, capsys):
    _workspace(tmp_path / "ws")
    skipped = []
    cases = list(corpus.workspace_cases(tmp_path / "ws", skipped))
    assert [(c.name, c.lane, c.expected) for c in cases] == [("1-alpha", "crypto", {"flag": "F{alpha}"}),
                                                             ("2-beta", "web", {"flag": "F{beta}"})]
    assert [w for _, w in skipped] == ["not solved (no flag.txt)"]

    mod = tmp_path / "mods"
    mod.mkdir()
    (mod / "gate_solver_fx.py").write_text(
        "from pathlib import Path\n"
        "def good(d):\n    return 'F{' + Path(d).name.split('-', 1)[1] + '}'\n"
        "def bad(d):\n    return 'F{nope}'\n")
    monkeypatch.syspath_prepend(str(mod))
    ws = str(tmp_path / "ws")
    assert corpus.main(["gate", "--workspace", ws, "--solver", "gate_solver_fx:good", "--budget", "web=5000"]) == 0
    assert "GATE PASS" in capsys.readouterr().out
    assert corpus.main(["gate", "--workspace", ws, "--solver", "gate_solver_fx:bad"]) == 1
    assert corpus.main(["gate", "--workspace", ws, "--solver", "gate_solver_fx:missing"]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert corpus.main(["gate", "--workspace", str(empty), "--solver", "gate_solver_fx:good"]) == 2


def test_gm_cases_load_saved_attempts(tmp_path):
    import hashlib
    art = b"delivery bytes"
    base = tmp_path / "day-03" / "warmups-day-03-thing"
    good = base / "time_trial"
    (good / "artifact").mkdir(parents=True)
    (good / "artifact" / "d.bin").write_bytes(art)
    attempt = {"attempt_id": "a1", "questions": [{"id": "q1", "normalization": "case_insensitive"}],
               "answer_ids": ["q1"], "artifacts": [{"filename": "d.bin", "sha256": hashlib.sha256(art).hexdigest()}]}
    (good / "attempt.json").write_text(json.dumps(attempt))
    (good / "key.json").write_text(json.dumps({"attempt_id": "a1", "answers": {"q1": "Value"}}))
    bad = base / "mastery"
    bad.mkdir()
    (bad / "attempt.json").write_text(json.dumps(dict(attempt, attempt_id="a2")))
    (bad / "key.json").write_text(json.dumps({"attempt_id": "a2", "answers": {"q1": "v"}}))

    skipped = []
    cases = list(corpus.gm_cases("warmups", tmp_path, skipped=skipped))
    assert len(cases) == 1
    c = cases[0]
    attempt_arg, dels, ctx = c.args
    assert dels[0].data == art and ctx["challenge"] == "warmups-day-03-thing/time_trial" and ctx["day"] == 3
    assert c.expected == {"q1": "Value"} and c.name == "day-03/warmups-day-03-thing/time_trial"
    assert skipped and "not saved" in skipped[0][1]
    rep = corpus.run_gate(cases, lambda a, d, x: {"q1": " value "})
    assert rep.ok          # case_insensitive normalization from the attempt
