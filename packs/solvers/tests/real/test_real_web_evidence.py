#!/usr/bin/env python3
"""The web_evidence toolkit on real artifacts: research-dataset scanner logs (Acunetix, Netsparker, w3af)
with counts checked by an independent line reader, ordinary Apache and nginx-JSON traffic, browser HARs, and
the shipped source of three Huntress web challenges (2024 'MOVEable', 2025 'Emotional' and 'Angler').

  .venv/bin/python tests/real/test_real_web_evidence.py    the real-file groups SKIP when challenges/_realdata/web_evidence is absent

Offline; the cache is filled by tests/real/fetch_c.py. The truth of each file is in the manifest's `what`.
"""
import collections
import re
import sys
import zipfile
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

we, ROOT = R.start("web_evidence")
check, q = R.check, R.q


def ev_of(rel):
    d = R.data(ROOT, rel)
    return d, we.Evidence(we.load_paths([ROOT / rel]) if (ROOT / rel).suffix == ".zip" else {Path(rel).name: d})


def line_truth(data):
    """A dumb independent reader: client, status and method of each access line, quotes and all."""
    ips, status = collections.Counter(), collections.Counter()
    n = 0
    for ln in data.decode("latin-1").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        s = ln[1:-1] if ln[:1] == '"' and ln[-1:] == '"' else ln
        m = re.match(r'(\S+) \S+ \S+ \[[^\]]+\] "(.*?)" (\d{3}) ', s)
        if not m:
            continue
        n += 1
        ips[m.group(1)] += 1
        status[m.group(3)] += 1
    return n, ips, status


def scanner_logs():
    for rel, client, tool in (("logs/acunetix.txt", "192.168.4.25", "acunetix"), ("logs/netsparker.txt", "192.168.4.164", "netsparker"),
                              ("logs/w3af.txt", None, "w3af")):
        d, ev = ev_of(rel)
        n, ips, status = line_truth(d)
        got = R.timed(f"solve_set on {rel}", we.solve_set, [q("n", "How many requests are in the log?", kind="integer"),
                      q("ips", "How many distinct IP addresses are in the log?", kind="integer"),
                      q("s", "How many requests returned status 404?", kind="integer"),
                      q("t", "Which tool did the attacker use to scan the site?")], {Path(rel).name: d}, {})
        check(f"{rel}: the three counts match an independent line reader", got["n"] == str(n) and got["ips"] == str(len(ips)) and got["s"] == str(status["404"]),
              (got["n"], got["ips"], got["s"], n, len(ips), status["404"]))
        check(f"{rel}: the scanner {tool} is offered (never plain: it is author vocabulary)", R.offers(got["t"], tool) and not R.plain(got["t"]), got["t"])
        if client:
            g = we.solve_set([q("ip", "What is the attacker's IP address?")], {Path(rel).name: d}, {})
            check(f"{rel}: one client, so the attacker IP is plain", g["ip"] == client, g["ip"])


def benign_traffic():
    for rel in ("logs/apache_logs", "logs/nginx_json_logs"):
        d = R.data(ROOT, rel)
        if rel.endswith("json_logs"):
            n = sum(1 for ln in d.decode().splitlines() if ln.strip())
            import json
            rows = [json.loads(ln) for ln in d.decode().splitlines() if ln.strip()]
            ips = {r["remote_ip"] for r in rows}
            s404 = sum(1 for r in rows if r["response"] == 404)
        else:
            n, ipc, status = line_truth(d)
            ips, s404 = set(ipc), status["404"]
        got = R.timed(f"solve_set on {rel}", we.solve_set, [q("n", "How many requests are in the log?", kind="integer"),
                      q("ips", "How many distinct IP addresses are in the log?", kind="integer"),
                      q("s", "How many requests returned status 404?", kind="integer"),
                      q("ip", "What is the attacker's IP address?"), q("v", "Which vulnerability was exploited?")], {Path(rel).name: d}, {})
        check(f"{rel}: the counts are right on ordinary traffic too", got["n"] == str(n) and got["ips"] == str(len(ips)) and got["s"] == str(s404), got)
        check(f"{rel}: no single attacker and no proven attack on benign traffic (unsure or None, never a plain wrong IP)",
              not R.plain(got["ip"]) and not R.plain(got["v"]), (got["ip"], got["v"]))


def hars():
    import json
    for rel in ("har/humanssuck.net.har", "har/cnn.har"):
        d = R.data(ROOT, rel)
        entries = json.loads(d)["log"]["entries"]
        n200 = sum(1 for e in entries if e["response"]["status"] == 200)
        whole = all(isinstance(e["response"].get("status"), int) and e["response"]["status"] for e in entries)
        got = R.timed(f"solve_set on {rel}", we.solve_set, [q("s", "How many requests returned status 200?", kind="integer"),
                      q("ip", "What is the attacker's IP address?"), q("v", "Which attack does the capture show?")], {Path(rel).name: d}, {})
        # cnn.har holds one aborted request (status 0): not every record has a status, so the count is None
        check(f"{rel}: 200-count plain when every entry has a status ({whole}), else None; no client address, no attack",
              (got["s"] == str(n200) if whole else got["s"] is None) and got["ip"] is None and not R.plain(got["v"]), got)


def moveable():
    R.data(ROOT, "huntress/moveable_app.zip")        # raises Skip (and prints why) when the cache is absent
    files = we.load_paths([ROOT / "huntress/moveable_app.zip"])
    src = we.read_source(files)
    sinks = src["sinks"]
    pick = [s for s in sinks if s["family"] == "deserialization"]
    check("MOVEable: the insecure deserialization is pickle.loads at app.py line 149",
          len(pick) == 1 and pick[0]["sink"] == "pickle.loads" and pick[0]["line"] == 149 and pick[0]["file"].endswith("app.py"), pick)
    sqli = [s for s in sinks if s["family"] == "sqli"]
    check("MOVEable: the string-built SQL executes are flagged and the parameterised ones are not (2 to 5 of them)", 2 <= len(sqli) <= 5, len(sqli))
    got = we.solve_set([q("r", "Which route holds the insecure deserialization? Answer the URL path."), q("f", "What dangerous function deserializes untrusted data?"),
                        q("l", "On which line is the insecure deserialization?", kind="integer"), q("x", "What is the vulnerability class of that call?")],
                       files, {})     # the opener runs tools/unpack.py first; here load_paths expanded the zip
    check("MOVEable: the route plain, the line plain, the sink and class unsure",
          got["r"] == "/download/<filename>/<sessionid>" and got["l"] == "149" and R.offers(got["f"], "pickle.loads") and not R.plain(got["f"])
          and not R.plain(got["x"]), got)


def emotional():
    files = {"server.js": R.data(ROOT, "huntress/emotional/server.js"), "views/index.ejs": R.data(ROOT, "huntress/emotional/views/index.ejs")}
    src = we.read_source(files)
    ssti = [s for s in src["sinks"] if s["family"] == "ssti"]
    check("Emotional: the one sink is the ejs.render template injection at server.js line 34",
          len(ssti) == 1 and ssti[0]["line"] == 34 and ssti[0]["file"] == "server.js", ssti)
    got = we.solve_set([q("x", "What vulnerability class does the application have?"), q("f", "Which dangerous function renders the template?"),
                        q("l", "On which line is the template injection?", kind="integer"), q("r", "Which route is vulnerable? Answer the URL path."),
                        q("p", "Which parameter is injected into the template?")], files, {})
    check("Emotional: class and sink unsure (ejs.render offered), line plain", not R.plain(got["x"]) and R.offers(got["f"], "ejs.render") and got["l"] == "34", got)
    check("Emotional: the sink's handler reads no request value, so route and parameter are unsure between the two routes",
          not R.plain(got["r"]) and R.offers(got["r"], "/setEmoji") and R.offers(got["r"], "/") and R.offers(got["p"], "emoji") and not R.plain(got["p"]), got)
    dr = R.drill(files, [q("x", "What is the vulnerability class of this web application's source?")])
    check("Emotional, end to end: web_evidence is the clear source match", dr["winner"] == "web_evidence", dr["rank"])


def angler_token():
    d = R.data(ROOT, "huntress/angler_access_token.json")
    got = we.solve_set([q("a", "Which algorithm signs the JWT?"), q("aud", "What is the aud claim of the token?")], {"access_token.json": d}, {})
    check("Angler token: alg RS256 and aud https://graph.microsoft.com/ are offered (token strings, unsure)",
          R.offers(got["a"], "RS256") and R.offers(got["aud"], "https://graph.microsoft.com/"), got)


for fn in (scanner_logs, benign_traffic, hars, moveable, emotional, angler_token):
    R.section(fn)
sys.exit(R.finish("test_real_web_evidence"))
