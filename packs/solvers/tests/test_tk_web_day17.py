#!/usr/bin/env python3
"""Day-17 look-ahead fixes to solvers/toolkits/web_evidence.py (findings W1 and W2).

  .venv/bin/python -m pytest tests/test_tk_web_day17.py   (or `python tests/test_tk_web_day17.py`)

No network, no token. A synthetic Apache access log (documentation IPs, no real target): five benign
requests from one client and three SQL-injection requests from the attacker.

W1 - an anaphoric per-actor count ("how many requests did THAT CLIENT make") is no longer answered with the
     grand total; it declines to None. A genuine total ("how many requests are in the log") still answers,
     and an explicit IP literal still gets that IP's own count.
W2 - an injection *technique* question gets its own labels key `web.technique/<fam>`, distinct from the
     attack *class* key `web.vuln/<fam>`, so a class probe cannot answer a technique id plain.
"""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_tk_web_day17_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.append(str(REPO / "solvers" / "common"))
_spec = importlib.util.spec_from_file_location("web_evidence", REPO / "solvers" / "toolkits" / "web_evidence.py")
we = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(we)
import labels   # noqa: E402

ATTACKER = "203.0.113.77"
BENIGN = "198.51.100.10"


def access_log() -> bytes:
    def line(ip, target, status, sec):
        return (f'{ip} - - [08/Oct/2026:13:{sec // 60:02d}:{sec % 60:02d} +0000] '
                f'"GET {target} HTTP/1.1" {status} {1200 + sec} "-" "curl/8.4.0"')
    rows, t = [], 0
    for _ in range(5):
        rows.append(line(BENIGN, "/products.php?id=12", 200, t)); t += 17
    rows.append(line(ATTACKER, "/products.php?id=12", 200, t)); t += 3
    rows.append(line(ATTACKER, "/products.php?id=12%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20-", 500, t)); t += 4
    rows.append(line(ATTACKER, "/products.php?id=-1%20UNION%20SELECT%20username,password%20FROM%20users--%20-", 200, t))
    return ("\n".join(rows) + "\n").encode()


FILES = {"access.log": access_log()}   # 8 events total; the attacker (203.0.113.77) made 3


def Q(aid, question, kind="exact_text", **fmt):
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question,
            "answer_format": {"kind": kind, **fmt}, "member": None}


def solve(*qs):
    we._CACHE.clear()
    return we.solve_set(list(qs), dict(FILES), {"attempt": {}})


def key_of(v):
    if not (isinstance(v, str) and v.startswith("??")):
        return None
    return json.loads(v[2:])["k"]


def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + str(detail)) if detail and not ok else ""))
    assert ok, name + (("  -- " + str(detail)) if detail else "")


# ---- W1 ----------------------------------------------------------------------------------------
def test_w1_anaphoric_actor_count_declines():
    r = solve(
        Q("web-total-requests", "How many requests are in the log?", kind="integer"),
        Q("web-attacker-request-count", "How many requests did that client make?", kind="integer"),
        Q("web-attacker-request-count-ip", f"How many requests did {ATTACKER} make?", kind="integer"),
    )
    check(r.get("web-total-requests") == "8",
          "W1: a genuine total ('how many requests are in the log') still answers len(events)=8 plain",
          r.get("web-total-requests"))
    check(r.get("web-attacker-request-count") is None,
          "W1: an anaphoric 'how many requests did THAT CLIENT make' declines to None, not the grand total",
          r.get("web-attacker-request-count"))
    check(r.get("web-attacker-request-count-ip") == "3",
          "W1: an explicit IP literal still gets that IP's own count (3), not the total",
          r.get("web-attacker-request-count-ip"))

    # the other anaphora spellings also decline
    for phr in ("the attacker", "this host", "the adversary", "that scanner", "this bot"):
        rr = solve(Q("web-actor-count", f"How many requests did {phr} send?", kind="integer"))
        check(rr.get("web-actor-count") is None, f"W1: '{phr}' count declines to None", rr.get("web-actor-count"))


# ---- W2 ----------------------------------------------------------------------------------------
def test_w2_technique_key_is_distinct_from_class_key():
    r2 = solve(
        Q("web-attack-class", "What vulnerability class was exploited?"),
        Q("web-sqli-technique", "What SQL injection technique was used?"),
    )
    kc = key_of(r2.get("web-attack-class"))
    kt = key_of(r2.get("web-sqli-technique"))
    check(kc is not None and kc.startswith("web.vuln/"),
          "W2: the attack-CLASS question keeps the judged web.vuln/<fam> key", (r2.get("web-attack-class"), kc))
    check(kt is not None and kt.startswith("web.technique/"),
          "W2: the TECHNIQUE question gets its own web.technique/<fam> key", (r2.get("web-sqli-technique"), kt))
    check(kc is not None and kt is not None and kc != kt,
          "W2: class and technique are distinct keys (a class probe cannot answer the technique id)", (kc, kt))
    # a question that names a class word beside 'technique' keeps the judged class key (conservative)
    rc = solve(Q("web-attack-class-2", "What class of attack technique was used?"))
    check(str(key_of(rc.get("web-attack-class-2")) or "").startswith("web.vuln/"),
          "W2: 'class ... technique' keeps the judged web.vuln key (ambiguous -> class)", rc.get("web-attack-class-2"))


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
