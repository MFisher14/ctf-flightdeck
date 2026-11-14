#!/usr/bin/env python3
"""evidence_core on real logs, and the incident-bundle drill (docs/toolkits/real-data.md).

  .venv/bin/python tests/real/test_real_evidence_core.py

SKIPs (exit 0) when challenges/_realdata/evidence_core is not there; tests/real/fetch_d.py fills
it. The files: loghub's 2,000-line samples of an sshd log, a syslog and an Apache error log (with
loghub's own structured CSV of the sshd log as the independent count), 10,000 lines of a real
combined access log, the Chinook sample database, an nmap XML report, the IIS log of Huntress
2025's "Webshellz" and the semicolon table of its "Trashcan" write-up. Every number asserted is
counted again here with csv, re, sqlite3 or a plain line count, never taken from the toolkit.

The drill: one delivery made of real files of five categories (an auth log, an IIS log, a pickle
that runs a command, an agent run with an injection, an npm package), ten questions, and each
question answered by the toolkit it belongs to. It needs the caches of ai_model_files,
agent_trace and repo_supply_chain too and is skipped (one line) without them.
"""
import csv
import io
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common_d as C                    # noqa: E402
from common_d import check, q, opts, timed     # noqa: E402

KIT = "evidence_core"
D = C.fetch_d.have(KIT)
if D is None:
    sys.exit(C.fetch_d.skip("tests/real/test_real_evidence_core.py", KIT))
T = C.toolkit(KIT)
ec = T
SLOW = []


def table(name, which=None):
    t, took = timed(lambda: ec.table(str(D / name), which) if which else ec.table(str(D / name)))
    n, took2 = timed(ec.q, t, "count")
    if took + took2 > 2.0:
        SLOW.append((name, round(took + took2, 2)))
    return t, n


def ask(files: dict, *questions):
    got, took = timed(T.solve_set, list(questions), files, {})
    if took > 2.0:
        SLOW.append(("solve_set " + ",".join(sorted(files))[:60], round(took, 2)))
    return [got[x["qid"]] for x in questions]


def test_ssh_and_syslog():
    name = "OpenSSH_2k.log"
    raw = (D / name).read_text()
    rows = list(csv.DictReader(io.StringIO((D / "OpenSSH_2k.log_structured.csv").read_text())))
    t, n = table(name)
    check("sshd log: a syslog table with one row per line of loghub's own parse (2,000), no line left unparsed",
          t.kind == "syslog" and n == len(rows) == 2000 and t.bad == 0, (t.kind, n, len(rows), t.bad))
    check("sshd log: as many distinct pids as loghub's parse has", len(ec.q(t, "distinct", "pid")) == len({r["Pid"] for r in rows}) == 519)
    top, tie = ec.q(t, "top", "ip", n=1)
    indep = Counter(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw)).most_common(1)[0]
    check("sshd log: the most common address is the one a regular expression over the file counts most", top[0][0] == indep[0] == "183.62.140.253" and not tie, (top, indep))
    data = (D / name).read_bytes()
    a = ask({"auth.log": data}, q("lines", "How many lines are in auth.log?", "integer", "auth.log"),
            q("top-ip", "Which source IP address appears most often in auth.log?", member="auth.log"))
    check("sshd log: the file has no final line end, so its line count is a pick of 2000 lines and wc's 1999, never plain",
          not data.endswith(b"\n") and opts(a[0]) == {"lines": "2000", "newlines": "1999"}, a[0])
    check("sshd log: the top address is offered under the method's name (the column is read out of free text)",
          opts(a[1]) == {"most_common.ip": "183.62.140.253"}, a[1])

    t, n = table("OpenSSH_2k.log_structured.csv")
    want = sum(1 for r in rows if r["EventId"] == "E24")
    a = ask({"events.csv": (D / "OpenSSH_2k.log_structured.csv").read_bytes()},
            q("e24", "How many rows in events.csv have EventId = E24?", "integer", "events.csv"),
            q("n", "How many rows are in events.csv?", "integer", "events.csv"))
    check("loghub's CSV: the header's nine columns, 2,000 rows, and a count by a column's own name is plain and right",
          t.kind == "csv" and list(t.columns) == list(rows[0].keys()) and n == 2000 and a[0] == str(want) == "413", (t.columns, n, a[0], want))
    check("loghub's CSV: 'how many rows' of a CSV stays a pick (data rows or lines)", (opts(a[1]) or {}).get("data_rows") == "2000", a[1])

    t, n = table("Linux_2k.log")
    check("a Linux syslog: 2,000 rows, none unparsed", t.kind == "syslog" and n == 2000 and t.bad == 0, (t.kind, n, t.bad))


def test_web_logs():
    name = "access.log"
    raw = (D / name).read_text(errors="replace")
    t, n = table(name)
    lines = raw.splitlines()
    check("combined access log: 10,000 rows, none unparsed", t.kind == "access" and n == len(lines) == 10000 and t.bad == 0, (t.kind, n, t.bad))
    want_404 = len(re.findall(r'" 404 ', raw))
    ip = Counter(ln.split(" ", 1)[0] for ln in lines).most_common(1)[0]
    check("combined access log: the 404 count, the busiest client and the distinct user agents, each as counted independently",
          ec.q(t, "count", where={"status": "404"}) == want_404 == 213 and ec.q(t, "top", "ip", n=1)[0][0] == ip == ("66.249.73.135", 482)
          and len(ec.q(t, "distinct", "user_agent")) == len({ln.rsplit('"', 2)[-2] for ln in lines if ln.count('"') >= 6}) == 558)
    a = ask({name: (D / name).read_bytes()}, q("s404", "How many rows in access.log have status = 404?", "integer", name))
    check("combined access log: the count by the column's own name is plain", a[0] == "213", a[0])

    name = "webshellz-HTTP.log"
    raw = (D / name).read_text()
    fields = re.search(r"(?m)^#Fields: (.+)$", raw).group(1).split()
    body = [ln.split() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
    t, n = table(name)
    check("2025 Webshellz, the IIS log: a table under the file's own #Fields columns, one row per request (28), no comment line counted",
          t.kind == "w3c" and list(t.columns) == fields and n == len(body) == 28 and t.bad == 0, (t.kind, t.columns[:4], n, len(body)))
    col = fields.index("sc-status")
    want = sum(1 for r in body if r[col] == "404")
    posts = sorted({r[fields.index("cs-uri-stem")] for r in body if r[fields.index("cs-method")] == "POST"})
    check("2025 Webshellz, the IIS log: status and method columns query like any table",
          ec.q(t, "count", where={"sc-status": "404"}) == want and sorted(ec.q(t, "distinct", "cs-uri-stem", where={"cs-method": "POST"})) == posts, (want, posts))
    a = ask({"u_ex251007.log": (D / name).read_bytes()}, q("s", "How many rows in u_ex251007.log have sc-status = 404?", "integer", "u_ex251007.log"))
    check("2025 Webshellz, the IIS log: the count by the column's own name is plain", a[0] == str(want), (a[0], want))

    name = "Apache_2k.log"
    raw = (D / name).read_text()
    t, n = table(name)
    check("Apache error log: rows with time, level and message; as many [error] rows as the file has",
          t.kind == "bracketed" and n == 2000 and t.bad == 0 and ec.q(t, "count", where={"level": "error"}) == len(re.findall(r"(?m)^\[[^\]]+\] \[error\]", raw)) == 595,
          (t.kind, n, t.bad))


def test_tables_of_other_kinds():
    name = "Chinook_Sqlite.sqlite"
    con = sqlite3.connect(f"file:{D / name}?mode=ro&immutable=1", uri=True)
    names = sorted(r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'"))
    tracks = con.execute("SELECT count(*) FROM Track").fetchone()[0]
    rock = con.execute("SELECT count(*) FROM Track WHERE GenreId = 1").fetchone()[0]
    con.close()
    got = sorted(t.name.split("#", 1)[1] for t in ec.tables(name, str(D / name)))
    t, n = table(name, "Track")
    check("Chinook: every table sqlite_master lists, and the Track table's rows and a filtered count as sqlite3 counts them",
          got == names and n == tracks == 3503 and ec.q(t, "count", where={"GenreId": "1"}) == rock, (got, n, tracks))
    t, n = table("trashcan-rbc_log2.csv")
    lines = [ln for ln in (D / "trashcan-rbc_log2.csv").read_text().splitlines() if ln.strip()]
    check("2025 Trashcan, the author's table: semicolon-separated, three columns, one row per line",
          t.kind == "csv" and t.meta["delimiter"] == ";" and len(t.columns) == 3 and n == len(lines), (t.kind, t.meta.get("delimiter"), n, len(lines)))
    t, n = table("nmap_example.xml")
    check("an nmap report: read as an XML table (its most repeated element)", t.kind == "xml" and n > 0, (t.kind, n))


# ---- the incident-bundle drill ---------------------------------------------------------------------------------

def test_bundle_drill():
    need = {"ai_model_files": "ps-malicious2_v4.pkl", "agent_trace": "agentdojo-workspace-ut0-it0.json", "repo_supply_chain": "husky-4.3.8.tgz"}
    paths = {k: C.fetch_d.path(k, v) for k, v in need.items()}
    if not all(paths.values()):
        print("note the bundle drill is skipped: it needs the caches of " + ", ".join(k for k, v in paths.items() if not v))
        return
    files = {}
    for name, p in (("auth.log", D / "OpenSSH_2k.log"), ("u_ex251007.log", D / "webshellz-HTTP.log"), ("model.pkl", paths["ai_model_files"]),
                    ("agent_run.json", paths["agent_trace"]), ("husky-4.3.8.tgz", paths["repo_supply_chain"])):
        C.run.expand(name, p.read_bytes(), files)
    qs = [q("auth-lines", "How many lines are in auth.log?", "integer", "auth.log"),
          q("iis-404", "How many rows in u_ex251007.log have sc-status = 404?", "integer", "u_ex251007.log"),
          q("ssh-top-ip", "Which source IP address appears most often in auth.log?", member="auth.log"),
          q("pickle-command", "What command does the pickle model.pkl execute on load?", member="model.pkl"),
          q("pickle-callable", "Which callable does the pickle model.pkl invoke when it is loaded?", member="model.pkl"),
          q("agent-exfil-tool", "Which tool did the agent use to exfiltrate data after the injection in agent_run.json?", member="agent_run.json"),
          q("agent-source-tool", "Which tool returned the injected instruction in the agent transcript?", member="agent_run.json"),
          q("npm-hook", "What command does the postinstall hook of the npm package run?", member="husky-4.3.8.tgz"),
          q("npm-name", "What is the name of the npm package?", member="husky-4.3.8.tgz"),
          q("attacker-ip", "What is the attacker's IP address?")]
    ctx = {}
    got, took = timed(T.solve_set, qs, files, ctx)
    routed = (ctx.get("evidence_core") or {}).get("routed") or {}
    check("drill: the evidence layer answers its own three (a line-count pick, a plain count, a top address) and hands none of them on",
          opts(got["auth-lines"]) == {"lines": "2000", "newlines": "1999"} and got["iis-404"] == "4" and opts(got["ssh-top-ip"]) == {"most_common.ip": "183.62.140.253"}
          and not {"auth-lines", "iis-404", "ssh-top-ip"} & set(routed), (got["auth-lines"], got["iis-404"], sorted(routed)))
    check("drill: each of the six other questions goes to the one toolkit of its file",
          {k: routed.get(k) for k in ("pickle-command", "pickle-callable", "agent-exfil-tool", "agent-source-tool", "npm-hook", "npm-name")} ==
          {"pickle-command": ["ai_model_files"], "pickle-callable": ["ai_model_files"], "agent-exfil-tool": ["agent_trace"],
           "agent-source-tool": ["agent_trace"], "npm-hook": ["repo_supply_chain"], "npm-name": ["repo_supply_chain"]}, routed)
    check("drill: the routed answers are the right ones, as their toolkits give them",
          got["pickle-command"] == "ls -la" and opts(got["pickle-callable"]) == {"public_module": "os.system", "as_pickled": "posix.system"}
          and got["agent-exfil-tool"] == "send_email" and got["agent-source-tool"] == "search_calendar_events"
          and opts(got["npm-hook"]) == {"command": "opencollective-postinstall || exit 0"} and opts(got["npm-name"]) == {"name": "husky"},
          {k: got[k] for k in routed})
    v = got["attacker-ip"]
    check("drill: 'the attacker's IP' names no file: whatever a toolkit says to it comes back as a pick or not at all, never plain",
          v is None or (isinstance(v, str) and v.startswith("??")), v)
    check("drill: ten questions over five real files in under 5 s", took < 5.0, round(took, 2))
    import os
    os.environ["CTF_BUNDLE_ROUTER"] = "off"
    try:
        off = T.solve_set(qs, files, {})
    finally:
        os.environ.pop("CTF_BUNDLE_ROUTER")
    check("drill: with CTF_BUNDLE_ROUTER=off the six questions stay None and the layer's own answers are the same",
          all(off[k] is None for k in ("pickle-command", "agent-exfil-tool", "npm-hook")) and off["iis-404"] == "4", off)
    sys.path.insert(0, str(C.REPO / "solvers" / "toolkits"))
    import registry
    ranked = [r["key"] for r in registry.rank(qs, files)["rows"]]
    check("drill: the triage ranking names the four specific toolkits and evidence_core for this bundle",
          {"agent_trace", "repo_supply_chain", "ai_model_files", "evidence_core"} <= set(ranked), ranked)


def test_cli():
    out = subprocess.run([sys.executable, str(C.REPO / "solvers" / "toolkits" / "evidence_core.py"), str(D / "webshellz-HTTP.log"), str(D / "Apache_2k.log")],
                         capture_output=True, text=True, timeout=120)
    check("the command: exit 0, the IIS log as a w3c table and the error log as a bracketed one",
          out.returncode == 0 and "w3c" in out.stdout and "bracketed" in out.stdout, out.stdout[:400] + out.stderr[-200:])


def main() -> int:
    for t in (test_ssh_and_syslog, test_web_logs, test_tables_of_other_kinds, test_bundle_drill, test_cli):
        try:
            t()
        except Exception as e:      # noqa: BLE001 - a crash on a real file is the finding
            check(f"{t.__name__} ran to its end", False, f"{type(e).__name__}: {e}")
    check("no file took a table pass or solve_set more than 2 s", not SLOW, SLOW)
    return C.finish("tests/real/test_real_evidence_core.py")


if __name__ == "__main__":
    sys.exit(main())
