#!/usr/bin/env python3
"""Offline tests of solvers/toolkits/net_dbproto.py (MQTT, Redis, MySQL, PostgreSQL, LDAP bind, syslog)
as wired into network.py. Synthetic RFC 5737 traffic only.

  .venv/bin/python -m pytest tests/test_day26_netforensics.py   (or `python tests/test_day26_netforensics.py`)

Proves (a) recovery on clean captures, as UNSURE picks never plain; (b) None on absent / ambiguous /
truncated / novel input; (c) a fuzz of junk through every reader and the full solve_set with
PLAIN(bad)=0 and no exceptions; (d) the hook fails safe (module absent = old behaviour).
"""
import json
import os
import random
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = str(Path(tempfile.mkdtemp(prefix="test_d26_")) / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import network as nw      # noqa: E402
import net_dbproto as nd  # noqa: E402


def check(name, cond, extra=""):
    print(("ok  " if cond else "FAIL") + f" {name}" + (f"  {extra}" if extra else ""))
    assert cond, name + (f"  {extra}" if extra else "")


def ip4(src, dst, payload, proto):
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b) + payload


def tcp(sport, dport, seq, data):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18, 65535, 0, 0) + data


def udp(sport, dport, data):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def eth(p):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + p


def pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + i, 1000 * i, len(f), len(f)) + f
    return out


CLI, SRV = "192.0.2.10", "192.0.2.200"


def conv(port, c2s, s2c=b"", cport=40000):
    fr = [eth(ip4(CLI, SRV, tcp(cport, port, 1000, c2s), 6))]
    if s2c:
        fr.append(eth(ip4(SRV, CLI, tcp(port, cport, 5000, s2c), 6)))
    return fr


def Q(text, aid, kind="exact_text"):
    return {"qid": aid, "answer_id": aid, "question": text, "answer_format": {"kind": kind, "syntax": "text"}}


def ask(frames, text, aid="q1"):
    return nw.solve_set([Q(text, aid)], {"cap.pcap": pcap(frames)}, {})[aid]


def opts(ans):
    if not isinstance(ans, str) or not ans.startswith("??"):
        return None
    return [v for _, v in json.loads(ans[2:])["o"]]


def s2(b):
    return struct.pack(">H", len(b)) + b


def vint(n):
    out = b""
    while True:
        b = n % 128
        n //= 128
        out += bytes([b | (128 if n else 0)])
        if not n:
            return out


def mq(t, fl, body):
    return bytes([(t << 4) | fl]) + vint(len(body)) + body


def mqtt_stream(user=b"sensor9", pw=b"hunter2x", cid=b"dev-cafe"):
    c = s2(b"MQTT") + b"\x04" + bytes([0xC2]) + b"\x00\x3c" + s2(cid) + s2(user) + s2(pw)
    pub = mq(3, 0, s2(b"home/temp") + b"21.5C")
    sub = mq(8, 2, b"\x00\x01" + s2(b"cmd/#") + b"\x00")
    return mq(1, 0, c) + pub + sub


def resp(*args):
    return b"*%d\r\n" % len(args) + b"".join(b"$%d\r\n%s\r\n" % (len(a), a) for a in args)


def mysql_pkt(seq, body):
    return struct.pack("<I", len(body))[:3] + bytes([seq]) + body


def mysql_login(user, db):
    caps = 0x200 | 0x8000 | 0x8 | 0x1
    body = struct.pack("<IIB", caps, 1 << 24, 33) + b"\x00" * 23 + user + b"\x00" + b"\x14" + b"\xaa" * 20 + db + b"\x00"
    return mysql_pkt(1, body)


def pg_startup(user, db):
    kv = b"user\x00" + user + b"\x00database\x00" + db + b"\x00\x00"
    return struct.pack(">II", 8 + len(kv), 196608) + kv


def pg_msg(t, body):
    return t + struct.pack(">I", len(body) + 4) + body


def ber(tag, content):
    n = len(content)
    ln = bytes([n]) if n < 128 else bytes([0x81, n])
    return bytes([tag]) + ln + content


def ldap_bind(mid, dn, pw):
    return ber(0x30, ber(2, bytes([mid])) + ber(0x60, ber(2, b"\x03") + ber(4, dn) + ber(0x80, pw)))


def ldap_resp(mid, code):
    return ber(0x30, ber(2, bytes([mid])) + ber(0x61, ber(10, bytes([code])) + ber(4, b"") + ber(4, b"")))


SYSL = b"<34>Oct 11 22:14:15 gw01 sshd[88]: Failed password"


# ---- (a) recovery ---------------------------------------------------------------------------------
def test_a_recovery():
    f = conv(1883, mqtt_stream())
    check("mqtt password", opts(ask(f, "In the MQTT capture, what password does the client send?")) == ["hunter2x"])
    check("mqtt username", opts(ask(f, "What username does the MQTT client authenticate with?")) == ["sensor9"])
    check("mqtt client id", opts(ask(f, "What is the MQTT client ID?")) == ["dev-cafe"])
    check("mqtt topic", opts(ask(f, "Which topic does the MQTT client publish to?")) == ["home/temp"])
    check("mqtt subscribe", opts(ask(f, "Which topic does the MQTT client subscribe to?")) == ["cmd/#"])
    check("mqtt never plain", ask(f, "What is the MQTT password?").startswith("??"))

    f = conv(6379, resp(b"AUTH", b"s3cretpw") + resp(b"SET", b"greeting", b"hello") + resp(b"GET", b"greeting"), b"+OK\r\n")
    check("redis password", opts(ask(f, "What password does the client use to AUTH to Redis?")) == ["s3cretpw"])
    check("redis set key", opts(ask(f, "Which Redis key is set by the client?")) == ["greeting"])
    check("redis set value", opts(ask(f, "What value is set in Redis?")) == ["hello"])

    greet = mysql_pkt(0, b"\x0a" + b"8.0.33-example\x00" + b"\x00" * 30)
    f = conv(3306, mysql_login(b"appuser", b"shopdb") + mysql_pkt(0, b"\x03SELECT 1"), greet)
    check("mysql version", opts(ask(f, "What MySQL server version is in the handshake?")) == ["8.0.33-example"])
    check("mysql user", opts(ask(f, "Which username logs in to the MySQL server?")) == ["appuser"])
    check("mysql db", opts(ask(f, "Which MySQL database does the client select?")) == ["shopdb"])
    check("mysql query", opts(ask(f, "What MySQL query is run?")) == ["SELECT 1"])

    srv = pg_msg(b"R", struct.pack(">I", 3))
    cl = pg_startup(b"dbadmin", b"inventory") + pg_msg(b"p", b"pgPass-1\x00") + pg_msg(b"Q", b"SELECT 2\x00")
    f = conv(5432, cl, srv)
    check("pg user", opts(ask(f, "Which user connects to PostgreSQL?")) == ["dbadmin"])
    check("pg database", opts(ask(f, "Which PostgreSQL database is requested?")) == ["inventory"])
    check("pg cleartext password", opts(ask(f, "What password does the PostgreSQL client send?")) == ["pgPass-1"])
    srv5 = pg_msg(b"R", struct.pack(">I", 5) + b"\x01\x02\x03\x04")
    md5 = b"md5" + b"0123456789abcdef" * 2
    f = conv(5432, pg_startup(b"dbadmin", b"inventory") + pg_msg(b"p", md5 + b"\x00"), srv5)
    check("pg md5 offered as md5 field only", opts(ask(f, "What is the PostgreSQL md5 hash sent?")) == [md5.decode()])
    check("pg md5 is no cleartext password", ask(f, "What password does the PostgreSQL client send?") is None)

    f = conv(389, ldap_bind(1, b"cn=admin,dc=corp,dc=example", b"Passw0rd!"), ldap_resp(1, 0))
    check("ldap password", opts(ask(f, "What password is used in the LDAP bind?")) == ["Passw0rd!"])
    check("ldap dn", opts(ask(f, "What DN does the LDAP client bind as?")) == ["cn=admin,dc=corp,dc=example"])

    f = [eth(ip4(CLI, SRV, udp(40000, 514, SYSL), 17))]
    check("syslog host", opts(ask(f, "What hostname sent the syslog message?")) == ["gw01"])
    check("syslog app", opts(ask(f, "Which program name is in the syslog message?")) == ["sshd"])
    check("syslog facility", opts(ask(f, "What is the syslog facility number?")) == ["4"])


# ---- (b) ambiguity / absence / truncation -> None -----------------------------------------------------
def test_b_ambiguity_absence_truncation_is_none():
    two = conv(1883, mqtt_stream(pw=b"aaaa1111")) + conv(1883, mqtt_stream(pw=b"bbbb2222"), cport=40001)
    check("ambiguous mqtt password is None", ask(two, "What is the MQTT password?") is None)
    check("absent protocol is None", ask(conv(80, b"GET / HTTP/1.1\r\n\r\n"), "What is the MQTT password?") is None)
    check("truncated mqtt is None", ask(conv(1883, mqtt_stream()[:12]), "What is the MQTT password?") is None)
    check("mqtt flag-shaped value withheld", ask(conv(1883, mqtt_stream(pw=b"flag{abc}")), "What is the MQTT password?") is None)
    check("redis with no AUTH is None", ask(conv(6379, resp(b"GET", b"k")), "What password is used to AUTH to Redis?") is None)
    check("ldap sasl bind is None",
          ask(conv(389, ber(0x30, ber(2, b"\x01") + ber(0x60, ber(2, b"\x03") + ber(4, b"cn=x") + ber(0xA3, b"\x04\x00")))),
              "What password is used in the LDAP bind?") is None)
    check("syslog malformed is None",
          ask([eth(ip4(CLI, SRV, udp(1, 514, b"<999>zzz"), 17))], "What hostname sent the syslog message?") is None)


# ---- (c) fuzz: PLAIN(bad)=0, no exceptions -----------------------------------------------------------------
def test_c_fuzz_no_plain_no_exception():
    rng = random.Random(26)
    texts = ["What is the MQTT password?", "Which Redis key is set?", "What MySQL user logs in?", "PostgreSQL password sent?",
             "LDAP bind password?", "syslog hostname?", "What is the MQTT topic?", "What is the PostgreSQL database?"]
    good = [mqtt_stream(), resp(b"AUTH", b"x") + resp(b"SET", b"a", b"b"), mysql_login(b"u", b"d"),
            pg_startup(b"u", b"d") + pg_msg(b"p", b"x\x00"), ldap_bind(1, b"cn=a", b"p"), SYSL]
    plain = n = 0
    for i in range(600):
        base = bytearray(rng.choice(good))
        mode = i % 4
        if mode == 0:
            base = bytearray(rng.randbytes(rng.randint(0, 120)))
        elif mode == 1 and base:
            for _ in range(rng.randint(1, 6)):
                base[rng.randrange(len(base))] = rng.randrange(256)
        elif mode == 2:
            base = base[:rng.randint(0, len(base))]
        port = rng.choice([1883, 6379, 3306, 5432, 389, 514, 1234])
        frames = conv(port, bytes(base), rng.randbytes(rng.randint(0, 40)) if i % 3 == 0 else b"")
        if port == 514:
            frames = [eth(ip4(CLI, SRV, udp(40000, 514, bytes(base)), 17))]
        try:
            res = nw.solve_set([Q(t, "q%d" % j) for j, t in enumerate(texts)], {"c.pcap": pcap(frames)}, {})
        except Exception as e:
            check("fuzz no exception", False, repr(e))
            break
        for v in res.values():
            n += 1
            if v is not None and not v.startswith("??"):
                plain += 1
    check("fuzz: 600 junk captures x 8 questions, PLAIN = 0", plain == 0, f"{n} answers, plain={plain}")

    for fn in (nd.mqtt_facts, nd.redis_facts, nd.mysql_facts, nd.pg_facts, nd.ldap_facts, nd.syslog_facts):
        bad = 0
        for i in range(150):
            cap = nw.read(pcap(conv(rng.choice([1883, 6379, 3306, 5432, 389]), rng.randbytes(rng.randint(0, 200)))))
            try:
                fn(cap)
            except Exception:
                bad += 1
        check(f"reader {fn.__name__} never raises on junk", bad == 0, f"raised {bad}/150")


# ---- (d) fail-safe hook ----------------------------------------------------------------------------------
def test_d_fail_safe_hook():
    f = conv(1883, mqtt_stream())
    before = ask(f, "What is the MQTT password?")
    orig = nw._sibling

    def _gone(name):
        if name == "net_dbproto":
            raise ImportError()
        return orig(name)

    nw._sibling = _gone
    try:
        after = ask(f, "What is the MQTT password?")
    finally:
        nw._sibling = orig
    check("hook off (module absent) -> None; hook on adds a pick only",
          after is None and before is not None and before.startswith("??"))


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
