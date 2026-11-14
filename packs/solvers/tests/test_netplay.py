#!/usr/bin/env python3
"""netplay harness -- drive each 2025 quiz/compute-over-a-socket pattern to the flag, offline.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_netplay.py   -> prints 'ok', exit 0

Stands up a LOCAL loopback socket server (one per scenario) that emulates the service: it sends a
prompt, checks our response equals the independently-computed correct answer, and only then emits a
CSCTF{...} flag. No real network, no external host. Asserts the driver + handler recover the flag for
clf_bytes_sum, xor_hex, b64_sort_concat, hmac_sha256_hex, hs256_jwt and tlv_sort_concat, plus the
auto-dispatcher and the scripted repl_shell_escape path.
"""
import base64
import hashlib
import hmac
import json
import socket
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import netplay as N  # noqa: E402


# --------------------------------------------------------------------------------------------------
# A tiny loopback emulator: serve one connection, run a scenario of (prompt, check) steps, emit flag.
# --------------------------------------------------------------------------------------------------

def serve_once(scenario, flag):
    """Start a server thread for one connection. Returns (host, port, join()).

    `scenario` is a list of (prompt_bytes, verify(resp_line)->bool). The server sends each prompt,
    reads one response line, verifies it; if every step verifies it sends the flag, else 'WRONG'.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    result = {"ok": None, "err": None}

    def _run():
        try:
            conn, _ = srv.accept()
            conn.settimeout(5.0)
            with conn:
                buf = b""
                for prompt, verify in scenario:
                    conn.sendall(prompt)
                    # read one line of response
                    while b"\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            raise RuntimeError("client closed early")
                        buf += chunk
                    line, buf = buf.split(b"\n", 1)
                    resp = line.decode("utf-8", "replace").strip()
                    if not verify(resp):
                        conn.sendall(b"WRONG\n")
                        result["ok"] = False
                        result["err"] = f"bad response {resp!r}"
                        return
                conn.sendall(flag.encode() + b"\n")
                result["ok"] = True
        except Exception as e:  # pragma: no cover - surfaced via result
            result["err"] = f"{type(e).__name__}: {e}"
        finally:
            srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    def join():
        t.join(timeout=10.0)
        return result

    return host, port, join


def drive(scenario, flag, handler, *, delims=None):
    """Run the emulator + the driver loop against it; return the flag the driver recovered."""
    host, port, join = serve_once(scenario, flag)
    conn = N.connect(host, port, timeout=5.0, prefer_pwntools=False)
    try:
        got = N.run_loop(conn, handler, delims=delims, timeout=5.0, quiet=0.25, max_rounds=20)
    finally:
        conn.close()
    res = join()
    return got, res


# --------------------------------------------------------------------------------------------------
# Scenarios -- one per pattern. Each independently computes the expected answer to verify against.
# --------------------------------------------------------------------------------------------------

FLAG = "CSCTF{n3tpl4y_dr0v3_th3_s0ck3t}"


def test_clf_bytes_sum():
    prompt = (
        b"Sum the BYTES of all log lines where METHOD is GET and the PATH starts with /api "
        b"and STATUS is 200.\n"
        b'10.0.0.1 - - [x] "GET /api/users HTTP/1.1" 200 100\n'
        b'10.0.0.2 - - [x] "GET /api/orders HTTP/1.1" 200 250\n'
        b'10.0.0.3 - - [x] "POST /api/orders HTTP/1.1" 200 999\n'
        b'10.0.0.4 - - [x] "GET /home HTTP/1.1" 200 500\n'
        b'10.0.0.5 - - [x] "GET /api/x HTTP/1.1" 404 42\n'
        b'10.0.0.6 - - [x] "GET /api/y HTTP/1.1" 200 -\n'
        b"Answer: "
    )
    expected = str(100 + 250)  # only the two GET /api 200 lines with numeric bytes
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.clf_bytes_sum)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_clf_bytes_sum_punct_and_boundary():
    # Prefix followed by a comma (punctuation must not be swallowed), and a segment boundary:
    # /apidocs shares the leading string but is NOT under /api, so it must be excluded.
    prompt = (
        b"Sum the BYTES where METHOD is GET, PATH starts with /api, and STATUS is 200.\n"
        b'10.0.0.1 - - [x] "GET /api/users HTTP/1.1" 200 100\n'
        b'10.0.0.2 - - [x] "GET /api/v10 HTTP/1.1" 200 7\n'       # genuinely under /api -> counts
        b'10.0.0.3 - - [x] "GET /apidocs HTTP/1.1" 200 5000\n'    # shares string, NOT under /api
        b'10.0.0.4 - - [x] "GET /api HTTP/1.1" 200 3\n'           # the prefix itself -> counts
        b"Answer: "
    )
    expected = str(100 + 7 + 3)  # 110; excludes /apidocs
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.clf_bytes_sum)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_clf_prefix_with_digits_and_period():
    # Path prefix containing a digit, stated at the end of a sentence with a trailing period.
    # /api/v1 must match /api/v1 and /api/v1/x but NOT /api/v10 (segment boundary).
    prompt = (
        b"Sum BYTES for GET requests whose PATH starts with /api/v1. STATUS 200 only.\n"
        b'1 - - [x] "GET /api/v1 HTTP/1.1" 200 10\n'
        b'2 - - [x] "GET /api/v1/x HTTP/1.1" 200 20\n'
        b'3 - - [x] "GET /api/v10 HTTP/1.1" 200 999\n'   # NOT under /api/v1
        b"> "
    )
    expected = str(10 + 20)  # 30; excludes /api/v10
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.clf_bytes_sum)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_xor_hex():
    data = [0xde, 0xad, 0xbe, 0xef]
    acc = 0
    for b in data:
        acc ^= b
    expected = f"{acc:02x}"
    prompt = b"XOR all of these hex bytes together: de-ad-be-ef\nResult: "
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.xor_hex)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_b64_sort_concat():
    msg = b"the quick brown fox jumps"
    parts = [msg[i:i + 5] for i in range(0, len(msg), 5)]
    # shuffle the index/fragment order deliberately
    order = [2, 0, 4, 1, 3]
    lines = []
    for idx in order:
        frag = base64.b64encode(parts[idx]).decode()
        lines.append(f"{idx}: {frag}")
    prompt = ("Decode each base64 fragment, sort by index, concatenate.\n"
              + "\n".join(lines) + "\n> ").encode()
    expected = msg.decode()
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.b64_sort_concat)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_hmac_sha256_hex():
    key, token, salt = "s3cr3tk3y", "abc123token", "NaCl99"
    expected = hmac.new(key.encode(), (token + salt).encode(), hashlib.sha256).hexdigest()
    prompt = (f"Compute HMAC-SHA256 of token||salt. key={key} token={token} salt={salt}\n"
              f"hex: ").encode()
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.hmac_sha256_hex)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_hs256_jwt():
    secret = "topsecret"
    payload = '{"user":"admin","role":"root"}'
    header = '{"alg":"HS256","typ":"JWT"}'

    def _b64url(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    def _canon(s):
        return json.dumps(json.loads(s), separators=(",", ":")).encode()

    h = _b64url(_canon(header))
    p = _b64url(_canon(payload))
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    expected = f"{h}.{p}.{_b64url(sig)}"

    prompt = (f"Forge an HS256 JWT. secret={secret} payload={payload}\n"
              f"token: ").encode()
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.hs256_jwt)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def _tlv(records):
    """records: list of (type_int, value_bytes) -> packed TLV hex string."""
    out = b""
    for t, v in records:
        out += bytes([t]) + len(v).to_bytes(2, "big") + v
    return out.hex()


def test_tlv_sort_concat():
    msg = b"assemble from tag one"
    parts = [msg[i:i + 4] for i in range(0, len(msg), 4)]
    # tag 0x01 fragments, out of order, each value = index byte + payload; plus decoy tag 0x02.
    recs = []
    order = list(range(len(parts)))
    shuffled = [order[i] for i in (3, 0, 4, 1, 2, 5)[:len(parts)]]
    for idx in shuffled:
        recs.append((0x01, bytes([idx]) + parts[idx]))
    recs.insert(2, (0x02, bytes([0]) + b"DECOY"))
    blob = _tlv(recs)
    prompt = (f"Parse the TLV (type,len BE,value); collect tag 0x01, sort by the index byte, concat.\n"
              f"{blob}\n> ").encode()
    expected = msg.decode()
    scenario = [(prompt, lambda r: r == expected)]
    got, res = drive(scenario, FLAG, N.tlv_sort_concat)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_multiply_char():
    # 2024 Multiply 1/2: repeat a single character N times. Multiply 2 uses punctuation/digits too.
    scenario = [
        (b"Repeat the character 'Q' 123 times.\n> ", lambda r: r == "Q" * 123),
        (b"Now give me '!' 7 times.\n> ", lambda r: r == "!" * 7),
        (b"And the digit '4' 40 times.\n> ", lambda r: r == "4" * 40),
    ]
    got, res = drive(scenario, FLAG, N.multiply_char)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_math_csv():
    # 2024 Math Master: reduce a CSV/space list by the stated operation, answer under 1s.
    nums = [12, 7, 5, 100, 3]
    scenario = [
        (f"Sum these numbers: {','.join(map(str, nums))}\n= ".encode(),
         lambda r: r == str(sum(nums))),
        (f"Compute the product of: {' '.join(map(str, nums))}\n= ".encode(),
         lambda r: r == str(12 * 7 * 5 * 100 * 3)),
        (b"Subtract in order: 100, 10, 5, 1\n= ", lambda r: r == str(100 - 10 - 5 - 1)),
        (b"What is the maximum of 3, 99, 42, 7?\n= ", lambda r: r == "99"),
    ]
    got, res = drive(scenario, FLAG, N.math_csv)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_country_capital():
    # 2024 Geography Master: country -> capital, from the static offline table. Multi-word names and
    # the trailing single-word substring must not steal a match (South Korea, not Korea by accident).
    scenario = [
        (b"What is the capital of France?\n> ", lambda r: r == "Paris"),
        (b"Capital city of South Korea?\n> ", lambda r: r == "Seoul"),
        (b"Name the capital of the United States.\n> ", lambda r: r == "Washington, D.C."),
        (b"Capital of Australia please:\n> ", lambda r: r == "Canberra"),
    ]
    got, res = drive(scenario, FLAG, N.country_capital)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_pwntools_quiz():
    # 2024 Pwntools: API trivia -> the exact token.
    scenario = [
        (b"Which function connects to a remote host and port over TCP?\n> ",
         lambda r: r == "remote"),
        (b"How do you receive data up to a given delimiter string?\n> ",
         lambda r: r == "recvuntil"),
        (b"Which function sends data followed by a newline?\n> ", lambda r: r == "sendline"),
        (b"What attribute sets the logging level / verbosity?\n> ",
         lambda r: r == "context.log_level"),
        (b"Which function receives all remaining data until the connection closes?\n> ",
         lambda r: r == "recvall"),
    ]
    got, res = drive(scenario, FLAG, N.pwntools_quiz)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_auto_dispatch_programming():
    """The auto-dispatcher routes the 2024 Programming archetypes across a multi-round service."""
    scenario = [
        (b"Repeat the character 'Z' 55 times.\n> ", lambda r: r == "Z" * 55),
        (b"Sum these numbers: 4,5,6\n> ", lambda r: r == "15"),
        (b"What is the capital of Japan?\n> ", lambda r: r == "Tokyo"),
        (b"In pwntools, which function connects to a remote host:port?\n> ",
         lambda r: r == "remote"),
    ]
    got, res = drive(scenario, FLAG, N.auto_handler)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_auto_dispatch_mixed():
    """The auto-dispatcher should pick the right handler per prompt across a multi-round service."""
    # Round 1: xor. Round 2: hmac. Then flag.
    xdata = [0x11, 0x22, 0x33]
    xacc = 0
    for b in xdata:
        xacc ^= b
    xexp = f"{xacc:02x}"
    key, token = "K", "T"
    hexp = hmac.new(key.encode(), token.encode(), hashlib.sha256).hexdigest()
    scenario = [
        (b"Round 1. XOR these hex bytes: 11 22 33\n> ", lambda r: r == xexp),
        (f"Round 2. Compute HMAC-SHA256. key={key} token={token}\n> ".encode(),
         lambda r: r == hexp),
    ]
    got, res = drive(scenario, FLAG, N.auto_handler)
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def test_repl_shell_escape_script():
    """The scripted send/expect path drives a REPL escape to the flag."""
    # Emulate a Julia-like REPL: banner, then expect the escape line, then 'cat /flag.txt'.
    host, port, join = _serve_repl(FLAG)
    conn = N.connect(host, port, timeout=5.0, prefer_pwntools=False)
    try:
        lines = N.repl_shell_escape("escape with run(`/bin/sh`) then read the flag")
        steps = [{"expect": "julia>", "send": lines[0]},
                 {"send": lines[1]}]
        got = N.run_script(conn, steps, timeout=5.0)
    finally:
        conn.close()
    res = join()
    assert res["ok"] is True, f"server rejected: {res}"
    assert got == FLAG, f"driver got {got!r}"


def _serve_repl(flag):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    result = {"ok": None, "err": None}

    def _run():
        try:
            conn, _ = srv.accept()
            conn.settimeout(5.0)
            with conn:
                conn.sendall(b"julia> ")
                buf = b""
                while b"\n" not in buf:
                    buf += conn.recv(65536)
                line1, buf = buf.split(b"\n", 1)
                if b"run(" not in line1 or b"/bin/sh" not in line1:
                    result["ok"] = False
                    result["err"] = f"bad escape {line1!r}"
                    return
                conn.sendall(b"sh-5.1$ ")
                while b"\n" not in buf:
                    buf += conn.recv(65536)
                line2, buf = buf.split(b"\n", 1)
                if b"cat /flag.txt" not in line2:
                    result["ok"] = False
                    result["err"] = f"bad read {line2!r}"
                    return
                conn.sendall(flag.encode() + b"\n")
                result["ok"] = True
        except Exception as e:  # pragma: no cover
            result["err"] = f"{type(e).__name__}: {e}"
        finally:
            srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    def join():
        t.join(timeout=10.0)
        return result

    return host, port, join


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[5:]}: line {where.lineno}: {str(e)[:900]}")
        except Exception as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[5:]}: raised {type(e).__name__}: {e} "
                  f"({Path(where.filename).name}:{where.lineno})")
        else:
            print(f"pass  {test.__name__[5:]}")
    print("ok" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
