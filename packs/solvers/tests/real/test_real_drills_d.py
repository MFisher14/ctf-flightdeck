#!/usr/bin/env python3
"""End-to-end drills of group d on Huntress challenges whose flag a write-up states
(docs/toolkits/real-data.md): the delivery saved as an attempt of an unknown lane, then what the
system does with nobody at the keyboard - `solvers/common/triage.py` writes the map,
`tools/lane_match.py` picks a solver as the opener would, and the winner's answer is compared
with the write-up's flag.

  .venv/bin/python tests/real/test_real_drills_d.py

SKIPs (exit 0) without the caches of repo_supply_chain, agent_trace and classical
(tests/real/fetch_d.py). The attempts are written under a temporary $CTF_WORKDIR; no
request is made (the Game Master URL is a closed port) and no token is read.

  drill              delivery                         expected
  ancient-fossil     ancient.fossil (2024)            closed alone: repo_supply_chain offers the flag
  darcy              darcy.tar.gz (2025)              closed alone: repo_supply_chain offers the flag
  the-void           output.txt, 12 MB (2024)         the flag is agent_trace's plain answer
  backdoored-splunk  Splunk_TA_windows.zip (2024)     with an agent: the map names the three changed files; the flag is on a live service
  cattle             cattle (2024)                    with an agent: no lane or toolkit claims a COW program; classical.py prints the flag
"""
import io
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import paths

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common_d as C                    # noqa: E402
from common_d import check, opts        # noqa: E402

sys.path.insert(0, str(C.REPO / "tests"))
import toolkit_fixtures as fx           # noqa: E402

RSC, AT, CL = C.fetch_d.have("repo_supply_chain"), C.fetch_d.have("agent_trace"), C.fetch_d.have("classical")
if not (RSC and AT and CL):
    sys.exit(C.fetch_d.skip("tests/real/test_real_drills_d.py", "repo_supply_chain, agent_trace and classical"))
CH = paths.workdir()
PY = sys.executable
FLAG_FORMAT = {"kind": "exact_text", "syntax": "flag{32 lowercase hex characters}", "pattern": r"^flag\{[0-9a-f]{32}\}$"}


def flag_q(qid, text, artifact):
    return {"id": qid, "question": text, "artifact": artifact, "answer_format": dict(FLAG_FORMAT), "normalization": "trim"}


def darcy_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in sorted((RSC / "darcy").rglob("*")):
            if f.is_file():
                info = tarfile.TarInfo("darcy/" + f.relative_to(RSC / "darcy").as_posix())
                data = f.read_bytes()
                info.size, info.mtime = len(data), 1759213107
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


DRILLS = [
    ("vcs-day-09-ancient-fossil", "ancient.fossil", lambda: (RSC / "ancient.fossil").read_bytes(), "Ancient Fossil",
     "What is the flag hidden in the repository's history?", "flag{2ed33f365669ea9f10b1a4ea4566fe8c}", "repo_supply_chain"),
    ("vcs-day-09-darcy", "darcy.tar.gz", darcy_tar, "Darcy",
     "What is the flag hidden in the repository's history?", "flag{a0c1e852e1281d134f0ac2b8615183a3}", "repo_supply_chain"),
    ("terminal-day-09-the-void", "output.txt", lambda: (AT / "the_void-output.txt").read_bytes(), "The Void",
     "What is the flag hidden in the terminal output?", "flag{b1370ac4fadd8c0237f8771d7d77286a}", "agent_trace"),
]


def run_drill(cid, filename, make, name, question, flag, kit):
    d = CH / "day-09" / cid
    case = {"filename": filename, "data": make(), "name": name, "questions": [flag_q("flag", question, filename)]}
    fx.write_attempt(d, case)
    t0 = time.monotonic()
    r = subprocess.run([PY, str(C.REPO / "solvers" / "common" / "triage.py"), str(d), "--quiet"], capture_output=True, text=True, timeout=180)
    took = time.monotonic() - t0
    md = (d / "triage.md").read_text() if (d / "triage.md").is_file() else ""
    section = md.split("## Toolkits", 1)[1] if "## Toolkits" in md else ""
    check(f"{name}: triage writes the map and its Toolkits section names {kit} and its page",
          r.returncode == 0 and f"docs/toolkits/{kit}.md" in section, (r.returncode, section[:300], r.stderr[-200:]))
    r = subprocess.run([PY, str(C.REPO / "tools" / "lane_match.py"), cid], capture_output=True, text=True, timeout=300, env=dict(os.environ))
    m = json.loads((d / "match.json").read_text()) if (d / "match.json").is_file() else {}
    rows = {c["lane"]: c for c in m.get("candidates") or []}
    winner = m.get("winner")
    print(f"note {name}: triage {took:.1f} s; lane_match winner={winner} ({m.get('why') or m.get('reason') or ''})"[:300])
    check(f"{name}: no lane solver claims it, and toolkit:{kit} answers the question",
          all(c.get("confident", 0) == 0 for n, c in rows.items() if not n.startswith("toolkit:"))
          and (rows.get("toolkit:" + kit) or {}).get("confident", 0) + (rows.get("toolkit:" + kit) or {}).get("unsure", 0) >= 1,
          {n: (c.get("confident"), c.get("unsure"), c.get("score")) for n, c in rows.items() if n.startswith("toolkit:") and (c.get("confident") or c.get("unsure"))})
    check(f"{name}: lane_match's winner is toolkit:{kit}", winner == "toolkit:" + kit, (winner, m.get("why")))
    sys.path.insert(0, str(C.REPO / "solvers" / "common"))
    import triage
    _, sets, _ = triage.load(d)
    qs, files, ctx = sets[0]
    got = C.toolkit(kit).solve_set(qs, files, ctx)
    v = got.get("flag")
    values = [v] if opts(v) is None else list(opts(v).values())
    check(f"{name}: the toolkit's answer to the flag question is the write-up's flag, and nothing else is offered", values == [flag], v)
    return winner


def test_flags():
    for row in DRILLS:
        try:
            run_drill(*row)
        except Exception as e:      # noqa: BLE001
            check(f"{row[3]}: the drill ran to its end", False, f"{type(e).__name__}: {e}")


def test_with_an_agent():
    # Backdoored Splunk II: the flag is behind a live service; what the files hold is which files were changed
    cid = "apps-day-09-backdoored-splunk"
    d = CH / "day-09" / cid
    q = {"id": "tampered-count", "question": "How many files of the app fail its manifest's integrity check?", "artifact": "Splunk_TA_windows.zip",
         "answer_format": {"kind": "integer", "syntax": "a whole number"}, "normalization": "trim"}
    fx.write_attempt(d, {"filename": "Splunk_TA_windows.zip", "data": (RSC / "Splunk_TA_windows.zip").read_bytes(), "name": "Backdoored Splunk II", "questions": [q]})
    out = subprocess.run([PY, str(C.REPO / "solvers" / "toolkits" / "repo_supply_chain.py"), str(d / "artifact" / "Splunk_TA_windows.zip")],
                         capture_output=True, text=True, timeout=120)
    check("Backdoored Splunk II: the toolkit's page names the backdoored script among the three files that fail the app's own manifest",
          out.stdout.count("MANIFEST MISMATCH") == 3 and "MANIFEST MISMATCH bin/powershell/dns-health.ps1" in out.stdout, out.stdout[:300])
    sys.path.insert(0, str(C.REPO / "solvers" / "common"))
    import triage
    _, sets, _ = triage.load(d)
    qs, files, ctx = sets[0]
    got = C.toolkit("repo_supply_chain").solve_set(qs, files, ctx)
    check("Backdoored Splunk II: the count of changed files is offered (3)", opts(got.get("tampered-count")) == {"mismatched": "3"}, got)

    # Cattle: a COW program in an unknown lane
    cid = "esolang-day-09-cattle"
    d = CH / "day-09" / cid
    fx.write_attempt(d, {"filename": "cattle", "data": (CL / "cattle").read_bytes(), "name": "Cattle",
                         "questions": [flag_q("flag", "What does the program print?", "cattle")]})
    r = subprocess.run([PY, str(C.REPO / "tools" / "lane_match.py"), cid], capture_output=True, text=True, timeout=300, env=dict(os.environ))
    m = json.loads((d / "match.json").read_text()) if (d / "match.json").is_file() else {}
    print(f"note Cattle: lane_match winner={m.get('winner')}")
    out = subprocess.run([PY, str(C.REPO / "solvers" / "common" / "classical.py"), str(d / "artifact" / "cattle"), "--seconds", "1"],
                         capture_output=True, text=True, timeout=120)
    check("Cattle: the agent's one command, classical.py on the file, prints the write-up's flag on its first line",
          out.stdout.splitlines()[:1] == ["KEYLESS cow                                flag{6cd6392eb609c6ae4c332ef6a321d9dd}"], out.stdout[:200])


def main() -> int:
    test_flags()
    try:
        test_with_an_agent()
    except Exception as e:      # noqa: BLE001
        check("the agent drills ran to their end", False, f"{type(e).__name__}: {e}")
    return C.finish("tests/real/test_real_drills_d.py")


if __name__ == "__main__":
    sys.exit(main())
