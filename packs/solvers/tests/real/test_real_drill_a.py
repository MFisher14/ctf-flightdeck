#!/usr/bin/env python3
"""End-to-end drills on real Huntress CTF challenges, group a (network, email, windows).

  .venv/bin/python tests/real/test_real_drill_a.py            the checks
  .venv/bin/python tests/real/test_real_drill_a.py --table    the same, and the result table as Markdown

Offline; SKIPs when the cache `challenges/_realdata/` is absent (tests/real/fetch_a.py fills it). Each
drill is a 2024 or 2025 challenge whose file is public and whose flag a public write-up states. The file
is saved as the base attempt of a made-up lane under a temporary CTF_WORKDIR, with the challenge's
own questions (or "What is the flag?" where the challenge asked only for a flag), and then what the opener
does for a new lane is run with no Game Master: solvers/common/triage.py (the map), tools/lane_match.py
(the five lane solvers and the toolkits, one process each), and the winner's answers
(`lane_match.py --one`). A drill is

  alone       the matched toolkit offers the write-up's answer for every question (plain, or as the first
              option of an unsure answer that tools/verify.py would probe on the untimed base);
  with agent  the toolkit is matched and its triage prints the fact, but a question is left for the agent;
  no          the answer is not in the files (OSINT, a live site).

The table goes into docs/toolkits/real-data.md. Nothing here is a claim about Day 9's wording: the
questions are the 2024 and 2025 authors', and no answer of these categories has been judged in this event.
"""
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from _real_a import REPO, TMP, check, finish
import fetch_a

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import paths

sys.path.insert(0, str(REPO / "tests"))
import toolkit_fixtures as fx       # noqa: E402
import labels                       # noqa: E402  (_real_a put solvers/common on the path)

ROOT = fetch_a.cache_root()
CH = paths.workdir()
PY = sys.executable
FLAG = "What is the flag?"


def zipped(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def q(qid, text, artifact, kind="exact_text"):
    return {"id": qid, "question": text, "artifact": artifact, "answer_format": {"kind": kind, "syntax": "exact artifact-derived value only"},
            "normalization": "trim"}


def cases() -> list:
    n, w, e = ROOT / "network", ROOT / "windows", ROOT / "email"
    out = []

    def add(slug, year, name, toolkit, filename, data, questions, expect):
        out.append({"slug": slug, "year": year, "name": name, "toolkit": toolkit, "filename": filename, "data": data,
                    "questions": [q(f"{slug}-{i + 1}", t, filename, k) for i, (t, k, _) in enumerate(questions)],
                    "key": {f"{slug}-{i + 1}": a for i, (_, _, a) in enumerate(questions)}, "expect": expect})

    add("echo", 2024, "Echo Chamber", "network", "echo_chamber.pcap", (n / "echo_chamber.pcap").read_bytes(),
        [(FLAG, "exact_text", "flag{6b38aa917a754d8bf384dc73fde633ad}")], "alone")
    add("keys", 2024, "Keyboard Junkie", "network", "keyboard_junkie", (n / "keyboard_junkie.pcap").read_bytes(),
        [(FLAG, "exact_text", "flag{f7733e0093b7d281dd0a30fcf34a9634}")], "alone")
    add("bus", 2025, "Bussing Around", "network", "bussing_around.pcapng", (n / "bussing_around.pcapng").read_bytes(),
        [(FLAG, "exact_text", "flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}")], "alone")
    add("zimmer", 2024, "Zimmer Down", "windows", "ntuser.dat", (w / "zimmer_down-ntuser.dat").read_bytes(),
        [(FLAG, "exact_text", "flag{4b676ccc1070be66b1a15dB601c8d500}")], "alone")
    add("streams", 2024, "Hidden Streams", "windows", "Challenge.zip", zipped({"Sysmon.evtx": (w / "hidden_streams-Sysmon.evtx").read_bytes()}),
        [(FLAG, "exact_text", "flag{bfefb891183032f44fa93d0c7bd40da9}")], "alone")
    add("trash", 2025, "Trashcan", "windows", "trashcan.zip", zipped({p.name: p.read_bytes() for p in sorted((w / "trashcan").iterdir())}),
        [(FLAG, "exact_text", "flag{1d2b2b05671ed1ee5812678850d5e329}")], "alone")
    add("night", 2024, "Nightmare on Hunt Street", "windows", "logs-parts1-5.zip",
        zipped({x: (w / f"nightmare-{x}").read_bytes() for x in ("Application.evtx", "Security.evtx", "System.evtx")}),
        [("What is the IP address of the host that the attacker used?", "exact_text", "10.1.1.42"),
         ("How many times was the compromised account brute-forced? Answer just the integer value.", "integer", "32"),
         ("What is the name of the offensive security tool that was used to gain initial access? Answer in all lowercase.", "exact_text", "psexec"),
         ("How many unique enumeration commands were run with net.exe? Answer just the integer value.", "integer", "3"),
         ("What password was successfully given to the user created?", "exact_text", "SusanIsStrong123")], "with agent")
    add("shop", 2024, "Little Shop of Hashes", "windows", "little_shop_of_hashes_logs.zip",
        zipped({f"hosts/{h}/{x}.evtx": (w / f"little_shop-{h}-{x}.evtx").read_bytes() for h in ("HOSTA", "HOSTB") for x in ("Security", "System", "Application")}),
        [("What is the name of the service that the attacker ran and stopped, which dumped hashes on the first compromised host?", "exact_text", "Remote Registry"),
         ("What lateral movement technique did the threat actor use to move to the other machine?", "exact_text", "Pass The Hash"),
         ("What is the full path of the binary that the threat actor used to access the privileges of a different user with explicit credentials?",
          "exact_text", "C:\\Users\\DeeDee\\Documents\\runasc.exe"),
         ("How many accounts were compromised by the threat actor?", "integer", "3"),
         ("What is the full path of the binary that was used to attempt a callback to the threat actor's machine?", "exact_text", "C:\\Users\\DeeDee\\Documents\\nc.exe")],
        "with agent")
    add("money", 2025, "Follow The Money", "email", "follow_the_money.zip",
        zipped({f"email {i} - FTM.eml": (e / f"ftm-email-{i}.eml").read_bytes() for i in range(1, 6)}),
        [(FLAG, "exact_text", "flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}")], "no")
    add("ran", 2024, "Ran Somewhere", "email", "ran_somewhere.eml", (e / "ran_somewhere.eml").read_bytes(),
        [(FLAG, "exact_text", "flag{...}")], "no")
    return out


def offered(answer):
    """(the value an answer offers first, 'plain' | 'unsure' | '-')."""
    if answer is None:
        return None, "-"
    p = labels.parse(answer) if isinstance(answer, str) else None
    if p is not None:
        return (p.options[0][1] if p.options else None), "unsure"
    return str(answer), "plain"


def main() -> int:
    if not all((ROOT / k).is_dir() for k in ("network", "windows", "email")):
        print(f"SKIP tests/real: the real-artifact cache is absent ({ROOT}); run tests/real/fetch_a.py")
        return 0
    rows = []
    for c in cases():
        cid = f"realdrill{c['slug']}-day-09-{c['slug']}"
        d = fx.write_attempt(CH / "day-09" / cid, {"filename": c["filename"], "data": c["data"], "questions": c["questions"], "name": c["name"],
                                                   "key": c["key"], "toolkit": c["toolkit"]})
        t = subprocess.run([PY, str(REPO / "solvers" / "common" / "triage.py"), str(d)], capture_output=True, text=True, timeout=300)
        tj = json.loads((d / "triage.json").read_text()) if (d / "triage.json").is_file() else {}
        kits = [k.get("key") for k in ((tj.get("toolkits") or {}).get("rows") or []) if isinstance(k, dict)]
        m = subprocess.run([PY, str(REPO / "tools" / "lane_match.py"), cid], capture_output=True, text=True, timeout=300)
        match = json.loads((d / "match.json").read_text()) if (d / "match.json").is_file() else {}
        winner = match.get("winner") or "-"
        solver = next((x.get("solver") for x in match.get("candidates") or [] if x.get("lane") == "toolkit:" + c["toolkit"]), None) \
            or str(REPO / "solvers" / "toolkits" / (c["toolkit"] + ".py"))
        one = subprocess.run([PY, str(REPO / "tools" / "lane_match.py"), "--one", solver, str(d), str(len(c["questions"]))], capture_output=True, text=True, timeout=300)
        try:
            ans = (json.loads(one.stdout.strip().splitlines()[-1]).get("answers") or {})
        except (ValueError, IndexError):
            ans = {}
        right = wrong_plain = 0
        marks = []
        for qq in c["questions"]:
            value, how = offered(ans.get(qq["id"]))
            good = value == c["key"][qq["id"]]
            right += good
            wrong_plain += (how == "plain" and not good)
            marks.append("=" if good and how == "plain" else "?" if good else "x" if how == "plain" else "~" if how == "unsure" else "-")
        got = "alone" if right == len(c["questions"]) else "no" if c["expect"] == "no" else "with agent"
        rows.append((c, kits[:2], winner, "".join(marks), right, got, wrong_plain))
        check(f"{c['year']} {c['name']}: the map is written and names `{c['toolkit']}` among its first two toolkits", t.returncode == 0 and c["toolkit"] in kits[:2], kits[:4] or t.stderr[-200:])
        check(f"{c['year']} {c['name']}: no plain answer is wrong", wrong_plain == 0, ans)
        if c["expect"] == "alone":
            check(f"{c['year']} {c['name']}: lane_match picks toolkit:{c['toolkit']} and it offers the write-up's flag (unsure: one base probe)",
                  winner == "toolkit:" + c["toolkit"] and got == "alone", (winner, ans))
        elif c["expect"] == "with agent":
            check(f"{c['year']} {c['name']}: {right} of {len(c['questions'])} of the challenge's own questions are offered right; the rest are left open, none wrong ({''.join(marks)})",
                  right < len(c["questions"]) and wrong_plain == 0, ans)
        else:
            check(f"{c['year']} {c['name']}: the flag is not in the files (the challenge leads to a web site): nothing is answered", right == 0 and all(x == "-" for x in marks), ans)
    night = next(r for r in rows if r[0]["slug"] == "night")
    check("Nightmare on Hunt Street: the 4625 count of question 2 is offered (32); question 5 has two candidate passwords in the logs and is left open",
          night[3][1] in "=?" and night[3][4] == "-", night[3])
    if "--table" in sys.argv:
        print("\n| year | challenge | category | delivered | triage's first toolkits | lane_match winner | per question | result |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for c, kits, winner, marks, right, got, _ in rows:
            print(f"| {c['year']} | {c['name']} | {c['toolkit']} | `{c['filename']}` | {', '.join(str(k) for k in kits) or '-'} | {winner} | `{marks}` | {got} |")
        print("\n`=` plain and right, `?` unsure with the right value first, `~` unsure with another value first, `x` plain and wrong, `-` not answered.")
    return finish("test_real_drill_a")


if __name__ == "__main__":
    sys.exit(main())
