"""B-244: the live, scope-locked, query-budgeted padding-oracle client (solvers/common/padding_oracle_live.py).

Every target is a fake service this test starts on 127.0.0.1 (in the suite's pinned live-service
scope, tests/conftest.py); keys and ciphertexts are made here. Nothing leaves loopback."""
from __future__ import annotations

import base64
import http.server
import json
import os
import socketserver
import threading
import time
import urllib.parse

import pytest
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

import crypto_oracles as co
import padding_oracle_live as POL
from ctf import ledger

KEY = bytes(range(16))
IV = bytes(range(16, 32))
SECRET = b"flag{loopback-oracle-only}"      # two CBC blocks
SHORT = b"flag{one-block}"                  # one block: the CLI test


def _cbc_encrypt(plain: bytes) -> bytes:
    return IV + AES.new(KEY, AES.MODE_CBC, IV).encrypt(co.pkcs7_pad(plain, 16))


def _padding_ok(blob: bytes) -> bool:
    if len(blob) < 32 or len(blob) % 16:
        return False
    plain = AES.new(KEY, AES.MODE_CBC, blob[:16]).decrypt(blob[16:])
    try:
        co.pkcs7_unpad(plain, 16)
        return True
    except ValueError:
        return False


# ---- fake services ------------------------------------------------------------------------------------------

class FakeHTTP:
    """GET /decrypt?c=<hex> (or POST with a base64 body) -> 200 "OK" | 500 "bad padding".
    After `rate_limit_after` queries it answers 429 "slow down" (neither verdict). Query number
    `huge_at` gets a 200 reply over the client's 1 MiB cap."""

    def __init__(self, check=_padding_ok, rate_limit_after=None, close_after=None, huge_at=None):
        self.check, self.count, self.rate_limit_after, self.close_after = check, 0, rate_limit_after, close_after
        self.huge_at = huge_at
        self.headers_seen: list[dict] = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True

            def log_message(self, *a):
                pass

            def _answer(self, blob):
                fake.count += 1
                fake.headers_seen.append(dict(self.headers))
                if fake.close_after is not None and fake.count > fake.close_after:
                    self.close_connection = True
                    self.wfile.flush()
                    self.connection.shutdown(2)
                    return
                if fake.huge_at is not None and fake.count == fake.huge_at:
                    code, body = 200, b"OK" + b"." * POL.MAX_REPLY
                elif fake.rate_limit_after is not None and fake.count > fake.rate_limit_after:
                    code, body = 429, b"slow down"
                elif fake.check(blob):
                    code, body = 200, b"OK"
                else:
                    code, body = 500, b"bad padding"
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                self._answer(bytes.fromhex(q["c"][0]))

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self._answer(base64.b64decode(self.rfile.read(n)))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FakeTCP:
    """Banner "oracle> ", then one hex line per query -> "yes\\n" | "no\\n"."""

    def __init__(self, check, huge_at=None):
        self.check, self.count, self.connections = check, 0, 0
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                fake.connections += 1
                self.wfile.write(b"welcome\noracle> ")
                for line in self.rfile:
                    fake.count += 1
                    if fake.count == huge_at:
                        # over 1 MiB with no end marker, then a stray verdict line the client must
                        # never read as the answer to a later query
                        try:
                            self.wfile.write(b"A" * (POL.MAX_REPLY + 4096) + b"yes\n")
                        except OSError:
                            return
                        continue
                    self.wfile.write(b"yes\n" if fake.check(bytes.fromhex(line.decode().strip())) else b"no\n")

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def http_fake():
    fakes = []

    def make(**kw):
        f = FakeHTTP(**kw)
        fakes.append(f)
        return f

    yield make
    for f in fakes:
        f.close()


@pytest.fixture
def tcp_fake():
    fakes = []

    def make(check, **kw):
        f = FakeTCP(check, **kw)
        fakes.append(f)
        return f

    yield make
    for f in fakes:
        f.close()


def _http_spec(port, **extra):
    raw = {"kind": "http", "url": f"http://127.0.0.1:{port}/", "path": "/decrypt?c={ct_hex}",
           "valid_status": [200], "invalid_status": [500]}
    raw.update(extra)
    return POL.OracleSpec.from_dict(raw)


def _budget(tmp_path, limit=None, cid="chal-1", **kw):
    return POL.QueryBudget(cid, limit=limit, workdir=tmp_path, **kw)


def _events(tmp_path, kind):
    return [r for r in ledger.read(tmp_path) if r["event"] == kind]


# ---- the CBC attack over HTTP --------------------------------------------------------------------------------

def test_cbc_decrypt_through_a_live_http_oracle(http_fake, tmp_path):
    fake = http_fake()
    budget = _budget(tmp_path, limit=20_000)
    with POL.LiveOracle(_http_spec(fake.port), budget) as oracle:
        out = POL.run_attack(oracle, "cbc-decrypt", ciphertext=_cbc_encrypt(SECRET))
    assert bytes.fromhex(out["result_hex"]) == SECRET and out["verified"] == "pkcs7-unpadded"
    assert out["queries"] == fake.count == budget.used == out["budget_used"]
    assert oracle.verdicts[True] >= 32 and oracle.verdicts[False] > 0
    assert [r["action"] for r in _events(tmp_path, "oracle.budget")] == ["set"]
    assert _events(tmp_path, "oracle.open")[0]["target"] == f"127.0.0.1:{fake.port}"
    close = _events(tmp_path, "oracle.close")
    assert len(close) == 1 and close[0]["queries"] == fake.count


def test_cbc_encrypt_forges_a_ciphertext_the_service_accepts(http_fake, tmp_path):
    fake = http_fake()
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=20_000)) as oracle:
        out = POL.run_attack(oracle, "cbc-encrypt", plaintext=b"admin=1")
    forged = bytes.fromhex(out["result_hex"])
    plain = AES.new(KEY, AES.MODE_CBC, forged[:16]).decrypt(forged[16:])
    assert co.pkcs7_unpad(plain, 16) == b"admin=1"


def test_post_body_and_header_templates_carry_the_ciphertext(http_fake, tmp_path):
    fake = http_fake()
    spec = _http_spec(fake.port, method="POST", path="/decrypt", body="{ct_b64}",
                      headers={"X-Len-Hex": "{ct_HEX}"})
    ct = _cbc_encrypt(b"hi")
    with POL.LiveOracle(spec, _budget(tmp_path, limit=5)) as oracle:
        assert oracle(ct) is True
        assert oracle(ct[:-1] + bytes([ct[-1] ^ 1])) is False
    assert fake.headers_seen[0]["X-Len-Hex"] == ct.hex().upper()


# ---- the per-challenge budget --------------------------------------------------------------------------------

def test_the_budget_stops_queries_before_they_are_sent(http_fake, tmp_path):
    fake = http_fake()
    budget = _budget(tmp_path, limit=10)
    with POL.LiveOracle(_http_spec(fake.port), budget) as oracle:
        with pytest.raises(co.OracleLimitError, match="budget"):
            POL.run_attack(oracle, "cbc-decrypt", ciphertext=_cbc_encrypt(SECRET))
    assert fake.count == 10 and budget.used == 10 and budget.remaining == 0


def test_the_budget_persists_across_runs_and_changes_only_with_extend(http_fake, tmp_path):
    fake = http_fake()
    ct = _cbc_encrypt(b"x")
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=3)) as oracle:
        oracle(ct)
        oracle(ct)
    again = _budget(tmp_path)                                     # a later run: no limit given
    assert (again.limit, again.used, again.remaining) == (3, 2, 1)
    assert _budget(tmp_path, limit=3).used == 2                   # the same limit is not a change
    with pytest.raises(POL.BudgetError, match="needs --extend"):
        _budget(tmp_path, limit=50)
    with pytest.raises(POL.BudgetError, match="needs --extend"):  # lowering is a change too
        _budget(tmp_path, limit=2)
    assert POL.QueryBudget.peek("chal-1", tmp_path) == {"challenge_id": "chal-1", "limit": 3, "used": 2}
    with POL.LiveOracle(_http_spec(fake.port), again) as oracle:
        oracle(ct)
        with pytest.raises(co.OracleLimitError):
            oracle(ct)
    assert fake.count == 3
    bigger = _budget(tmp_path, limit=5, extend=True, by="max")
    assert (bigger.limit, bigger.used, bigger.remaining) == (5, 3, 2)
    ext = [r for r in _events(tmp_path, "oracle.budget") if r["action"] == "extend"]
    assert len(ext) == 1 and (ext[0]["previous"], ext[0]["limit"], ext[0]["used"], ext[0]["by"]) == (3, 5, 3, "max")
    assert POL.QueryBudget.peek("chal-1", tmp_path) == {"challenge_id": "chal-1", "limit": 5, "used": 3}
    assert POL.QueryBudget.peek("other", tmp_path) is None


def test_budgets_are_per_challenge(tmp_path):
    a = _budget(tmp_path, limit=1, cid="a")
    b = _budget(tmp_path, limit=1, cid="b")
    a.take()
    with pytest.raises(co.OracleLimitError):
        a.take()
    assert b.take() == 1


def test_a_first_run_without_a_limit_is_refused(tmp_path):
    with pytest.raises(POL.BudgetError, match="--max-queries"):
        _budget(tmp_path)
    assert not (tmp_path / "oracle" / "chal-1.json").exists()


@pytest.mark.parametrize("cid", ["../escape", "a/b", "", ".hidden", "x" * 129])
def test_challenge_ids_cannot_leave_the_oracle_folder(tmp_path, cid):
    with pytest.raises(ValueError, match="challenge id"):
        _budget(tmp_path, limit=1, cid=cid)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, co.MAX_QUERIES + 1])
def test_bad_limits_are_refused(tmp_path, limit):
    with pytest.raises(ValueError, match="max queries"):
        _budget(tmp_path, limit=limit)


def test_a_foreign_budget_file_is_refused_not_guessed(tmp_path):
    (tmp_path / "oracle").mkdir()
    (tmp_path / "oracle" / "chal-1.json").write_text(json.dumps({"challenge_id": "other", "limit": 9, "used": 0}))
    with pytest.raises(POL.BudgetError, match="refusing to guess"):
        _budget(tmp_path)


def test_concurrent_takes_never_exceed_the_limit(tmp_path):
    _budget(tmp_path, limit=40)
    got, errors = [], []

    def worker():
        b = _budget(tmp_path)
        for _ in range(20):
            try:
                got.append(b.take())
            except co.OracleLimitError:
                errors.append(1)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(got) == list(range(1, 41)) and len(errors) == 40


# ---- scope lock ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["oracle.public-target.example.com", "8.8.8.8", "board.suite-platform.test"])
def test_out_of_scope_targets_are_refused_before_any_query(tmp_path, host):
    spec = POL.OracleSpec.from_dict({"kind": "http", "url": f"https://{host}/", "valid_status": [200]})
    budget = _budget(tmp_path, limit=5)
    with pytest.raises(POL.OutOfScope):
        POL.LiveOracle(spec, budget)
    assert budget.remaining == 5 and _events(tmp_path, "oracle.open") == []


def test_a_narrow_profile_refuses_loopback_too(http_fake, tmp_path):
    from ctf import event
    import datetime as dt
    prof = event.parse({
        "slug": "narrow", "name": "narrow", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.narrow.test"}, "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["*.narrow.test"]}}, src="test")
    fake = http_fake()
    with pytest.raises(POL.OutOfScope, match="narrow"):
        POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=5), profile=prof)
    assert fake.count == 0


# ---- verdicts and transport ---------------------------------------------------------------------------------

def test_an_answer_matching_neither_rule_is_a_protocol_error(http_fake, tmp_path):
    fake = http_fake(rate_limit_after=2)
    ct = _cbc_encrypt(b"x")
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=10)) as oracle:
        assert oracle(ct) is True
        assert oracle(ct[:-1] + bytes([ct[-1] ^ 1])) is False
        with pytest.raises(co.OracleProtocolError, match="neither"):
            oracle(ct)


def test_with_only_a_validity_rule_anything_else_is_invalid(http_fake, tmp_path):
    fake = http_fake(rate_limit_after=0)
    spec = POL.OracleSpec.from_dict({"kind": "http", "url": f"http://127.0.0.1:{fake.port}/decrypt?c={{ct_hex}}",
                                     "valid_regex": "^OK$"})
    assert spec.path == "/decrypt?c={ct_hex}"
    with POL.LiveOracle(spec, _budget(tmp_path, limit=2)) as oracle:
        assert oracle(_cbc_encrypt(b"x")) is False                # 429 "slow down" is not "OK"


def test_status_and_regex_must_both_match_for_valid(tmp_path):
    spec = _http_spec(1, valid_regex="^OK$", invalid_regex="padding")
    o = POL.LiveOracle(spec, _budget(tmp_path, limit=1))
    assert o.verdict(200, b"OK") is True
    assert o.verdict(500, b"bad padding") is False
    with pytest.raises(co.OracleProtocolError):
        o.verdict(200, b"server error")
    with pytest.raises(co.OracleProtocolError):
        o.verdict(500, b"OK")


def test_a_dropped_connection_is_a_transport_error_not_a_verdict(http_fake, tmp_path):
    fake = http_fake(close_after=1)
    ct = _cbc_encrypt(b"x")
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=5)) as oracle:
        assert oracle(ct) is True
        with pytest.raises(POL.OracleTransportError):
            oracle(ct)
        assert oracle.verdicts == {True: 1, False: 0}


def test_an_oversized_reply_drops_the_connection_so_the_next_query_works(http_fake, tmp_path):
    """The rest of an over-1-MiB body is still unread on the persistent connection; the client must
    close it, or the next request fails on the half-read response (http.client ResponseNotReady)."""
    fake = http_fake(huge_at=1)
    ct = _cbc_encrypt(b"x")
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=5)) as oracle:
        with pytest.raises(POL.OracleTransportError, match="1 MiB"):
            oracle(ct)
        assert oracle(ct) is True
        assert oracle(ct[:-1] + bytes([ct[-1] ^ 1])) is False
        assert oracle.verdicts == {True: 1, False: 1} and fake.count == 3


def test_the_ledger_records_whether_verdicts_are_strict(http_fake, tmp_path):
    fake = http_fake()
    ct = _cbc_encrypt(b"x")
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=5, cid="strict")) as oracle:
        oracle(ct)
    loose = POL.OracleSpec.from_dict({"kind": "http", "url": f"http://127.0.0.1:{fake.port}/",
                                      "path": "/decrypt?c={ct_hex}", "valid_status": [200]})
    assert loose.strict is False and _http_spec(fake.port).strict is True
    assert _http_spec(fake.port, invalid_status=[], invalid_regex="padding").strict is True
    with POL.LiveOracle(loose, _budget(tmp_path, limit=5, cid="loose")) as oracle:
        oracle(ct)
    opened = {r["challenge_id"]: r["verdicts"] for r in _events(tmp_path, "oracle.open")}
    assert opened == {"strict": "strict", "loose": "valid-only"}


def test_a_closed_port_is_a_transport_error(tmp_path):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    spec = POL.OracleSpec.from_dict({"kind": "tcp", "host": "127.0.0.1", "port": port, "valid_regex": "yes",
                                     "timeout": 5})
    with POL.LiveOracle(spec, _budget(tmp_path, limit=2)) as oracle:
        with pytest.raises(POL.OracleTransportError, match="tcp query"):
            oracle(b"\x00" * 32)


# ---- RSA oracles over TCP and HTTP ------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa512():
    """A 512-bit key (OAEP-SHA1 fits; fewer oracle round trips than RSA.generate's 1024-bit minimum)."""
    import random
    import sympy
    rng = random.Random(512)
    while True:
        p, q = (sympy.nextprime(rng.getrandbits(256) | (1 << 255)) for _ in range(2))
        n, phi = p * q, (p - 1) * (q - 1)
        if n.bit_length() == 512 and phi % 65537:
            return RSA.construct((n, 65537, pow(65537, -1, phi), p, q))


def test_rsa_lsb_over_a_persistent_tcp_connection(tcp_fake, tmp_path, rsa512):
    k = rsa512
    size = (k.n.bit_length() + 7) // 8
    fake = tcp_fake(lambda ct: pow(int.from_bytes(ct, "big"), k.d, k.n) & 1 == 1)
    m = int.from_bytes(b"lsb-secret", "big")
    c = pow(m, k.e, k.n)
    spec = POL.OracleSpec.from_dict({"kind": "tcp", "host": "127.0.0.1", "port": fake.port, "send": "{ct_hex}\n",
                                     "banner_until": "oracle> ", "reply_until": "\n",
                                     "valid_regex": "^yes$", "invalid_regex": "^no$"})
    with POL.LiveOracle(spec, _budget(tmp_path, limit=5000)) as oracle:
        out = POL.run_attack(oracle, "rsa-lsb", ciphertext=c.to_bytes(size, "big"), n=k.n, e=k.e)
    assert int(out["result_hex"], 16) == m and out["verified"] == "re-encrypts"
    assert fake.connections == 1 and fake.count == out["queries"]


def test_an_oversized_tcp_reply_drops_the_connection_so_later_verdicts_stay_in_step(tcp_fake, tmp_path):
    """After a transport error the socket and its read buffer still hold the rest of that answer;
    the client must drop both, or every later query reads the answer to the query before it."""
    fake = tcp_fake(lambda ct: ct == b"\x01", huge_at=1)
    spec = POL.OracleSpec.from_dict({"kind": "tcp", "host": "127.0.0.1", "port": fake.port, "send": "{ct_hex}\n",
                                     "banner_until": "oracle> ", "reply_until": "\n",
                                     "valid_regex": "^yes$", "invalid_regex": "^no$", "timeout": 30})
    with POL.LiveOracle(spec, _budget(tmp_path, limit=5)) as oracle:
        with pytest.raises(POL.OracleTransportError, match="1 MiB"):
            oracle(b"\x01")
        assert oracle(b"\x02") is False
        assert oracle(b"\x01") is True
        assert oracle(b"\x02") is False
        assert oracle.verdicts == {True: 1, False: 2}
    assert fake.connections == 2


def test_a_non_persistent_tcp_spec_reconnects_per_query(tcp_fake, tmp_path):
    fake = tcp_fake(lambda ct: True)
    spec = POL.OracleSpec.from_dict({"kind": "tcp", "host": "127.0.0.1", "port": fake.port, "persistent": False,
                                     "banner_until": "oracle> ", "valid_regex": "yes"})
    with POL.LiveOracle(spec, _budget(tmp_path, limit=3)) as oracle:
        assert [oracle(b"\x01"), oracle(b"\x02"), oracle(3)] == [True, True, True]
    assert fake.connections == 3


def test_manger_over_http_post(http_fake, tmp_path, rsa512):
    k = rsa512
    size = (k.n.bit_length() + 7) // 8
    B = 1 << (8 * (size - 1))
    fake = http_fake(check=lambda ct: pow(int.from_bytes(ct, "big"), k.d, k.n) < B)
    ct = PKCS1_OAEP.new(k.publickey(), randfunc=__import__("random").Random(1).randbytes).encrypt(b"manger works")
    spec = _http_spec(fake.port, method="POST", path="/decrypt", body="{ct_b64}")
    with POL.LiveOracle(spec, _budget(tmp_path, limit=20_000)) as oracle:
        out = POL.run_attack(oracle, "manger", ciphertext=ct, n=k.n, e=k.e)
    assert bytes.fromhex(out["result_hex"]) == b"manger works" and out["verified"] == "re-encrypts"
    assert fake.count == out["queries"] < 20_000


def test_rsa_attacks_need_the_public_key(http_fake, tmp_path):
    fake = http_fake()
    with POL.LiveOracle(_http_spec(fake.port), _budget(tmp_path, limit=5)) as oracle:
        with pytest.raises(ValueError, match="needs --n and --e"):
            POL.run_attack(oracle, "bleichenbacher", ciphertext=b"\x01")
        with pytest.raises(ValueError, match="attack must be"):
            POL.run_attack(oracle, "timing", ciphertext=b"\x01")
    assert fake.count == 0


# ---- pacing (a wall-clock behaviour: only a lower bound is asserted) ------------------------------------------

def test_min_interval_spaces_queries(tcp_fake, tmp_path):
    fake = tcp_fake(lambda ct: True)
    spec = POL.OracleSpec.from_dict({"kind": "tcp", "host": "127.0.0.1", "port": fake.port,
                                     "banner_until": "oracle> ", "valid_regex": "yes", "min_interval": 0.2})
    with POL.LiveOracle(spec, _budget(tmp_path, limit=3)) as oracle:
        t0 = time.monotonic()
        for i in range(3):
            oracle(bytes([i]))
        assert time.monotonic() - t0 >= 0.4


# ---- spec and templates -------------------------------------------------------------------------------------

def test_render_placeholders():
    ct = b"\x00\xff>?"
    assert POL.render("{ct_hex}|{ct_HEX}|{ct_b64}|{ct_b64url}|{ct_int}", ct) == \
        f"00ff3e3f|00FF3E3F|AP8+Pw==|AP8-Pw|{int.from_bytes(ct, 'big')}"
    with pytest.raises(ValueError, match="bad placeholder"):
        POL.render("{ciphertext}", ct)


@pytest.mark.parametrize("raw, why", [
    ({"kind": "udp", "host": "127.0.0.1", "port": 1, "valid_regex": "x"}, "kind"),
    ({"kind": "http", "url": "ftp://127.0.0.1/", "valid_status": [200]}, "bad http url"),
    ({"kind": "http", "valid_status": [200]}, "needs url"),
    ({"kind": "tcp", "host": "127.0.0.1", "valid_regex": "x"}, "host and port"),
    ({"kind": "tcp", "host": "127.0.0.1", "port": 1}, "validity rule"),
    ({"kind": "tcp", "host": "127.0.0.1", "port": 1, "valid_status": [200]}, "http specs only"),
    ({"kind": "tcp", "host": "127.0.0.1", "port": 70000, "valid_regex": "x"}, "port"),
    ({"kind": "tcp", "host": "127.0.0.1", "port": 1, "valid_regex": "x", "token": "s"}, "unknown spec keys"),
    ({"kind": "http", "url": "http://127.0.0.1/", "valid_status": ["200"]}, "list of integers"),
    ({"kind": "tcp", "host": "127.0.0.1", "port": 1, "valid_regex": "x", "timeout": 0}, "timeout"),
])
def test_bad_specs_are_refused(raw, why):
    with pytest.raises(ValueError, match=why):
        POL.OracleSpec.from_dict(raw)


def test_spec_loads_from_toml_and_json(tmp_path):
    t = tmp_path / "o.toml"
    t.write_text('kind = "tcp"\nhost = "127.0.0.1"\nport = 31337\nvalid_regex = "yes"\n')
    j = tmp_path / "o.json"
    j.write_text(json.dumps({"kind": "http", "url": "https://127.0.0.1:8443/x?y=1", "valid_status": [200]}))
    assert POL.OracleSpec.load(t).port == 31337
    s = POL.OracleSpec.load(j)
    assert (s.scheme, s.host, s.port, s.path) == ("https", "127.0.0.1", 8443, "/x?y=1")


# ---- CLI ----------------------------------------------------------------------------------------------------

def test_cli_run_probe_status_and_exit_codes(http_fake, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    fake = http_fake()
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"kind": "http", "url": f"http://127.0.0.1:{fake.port}/",
                                "path": "/decrypt?c={ct_hex}", "valid_status": [200], "invalid_status": [500]}))
    ct = _cbc_encrypt(SHORT).hex()

    assert POL.main(["status", "--challenge", "c1"]) == 1
    assert json.loads(capsys.readouterr().out)["budget"] is None
    assert POL.main(["probe", "--spec", str(spec), "--challenge", "c1", "--ciphertext", ct]) == 2
    assert "--max-queries" in capsys.readouterr().err                   # no budget yet
    assert POL.main(["probe", "--spec", str(spec), "--challenge", "c1", "--ciphertext", ct,
                     "--max-queries", "20000"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"valid": True, "budget_used": 1, "budget_limit": 20000}
    assert "warning" not in captured.err                                # a strict spec: no warning
    assert POL.main(["run", "--spec", str(spec), "--challenge", "c1", "--attack", "cbc-decrypt",
                     "--ciphertext", ct]) == 0
    out = json.loads(capsys.readouterr().out)
    assert bytes.fromhex(out["result_hex"]) == SHORT and out["budget_used"] == fake.count
    assert POL.main(["status", "--challenge", "c1"]) == 0
    assert json.loads(capsys.readouterr().out)["used"] == fake.count

    used = fake.count
    assert POL.main(["run", "--spec", str(spec), "--challenge", "c2", "--attack", "cbc-decrypt",
                     "--ciphertext", ct, "--max-queries", "5"]) == 5
    assert "budget" in capsys.readouterr().err and fake.count == used + 5

    far = tmp_path / "far.json"
    far.write_text(json.dumps({"kind": "http", "url": "http://203.0.113.0.example.org/", "valid_status": [200]}))
    assert POL.main(["probe", "--spec", str(far), "--challenge", "c3", "--ciphertext", ct,
                     "--max-queries", "1"]) == 4
    assert "refused" in capsys.readouterr().err
    assert fake.count == used + 5


def test_cli_warns_when_a_spec_has_no_invalid_rule(http_fake, tmp_path, monkeypatch, capsys):
    """Valid-only verdicts read a 429 or an error page as "invalid padding"; the CLI says so on stderr
    before the run (the run itself goes ahead: the operator may mean it)."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    fake = http_fake()
    spec = tmp_path / "loose.json"
    spec.write_text(json.dumps({"kind": "http", "url": f"http://127.0.0.1:{fake.port}/",
                                "path": "/decrypt?c={ct_hex}", "valid_regex": "^OK$"}))
    ct = _cbc_encrypt(SHORT).hex()
    assert POL.main(["probe", "--spec", str(spec), "--challenge", "w1", "--ciphertext", ct,
                     "--max-queries", "3"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["valid"] is True
    assert "warning" in captured.err and "no invalid rule" in captured.err
