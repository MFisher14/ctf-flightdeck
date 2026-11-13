#!/usr/bin/env python3
"""End-to-end drills of group b on real challenge files (SKIPs without the cache of fetch_b.py).

  .venv/bin/python tests/real/test_real_drills_b.py

Each drill saves the real file as an attempt folder in a scratch directory (attempt.json and
artifact/, as tools/verify.py --start saves one), runs solvers/common/triage.py on it as the opener
does for a lane it does not know, reads which toolkit the map names first, and asks that toolkit
the challenge's own question. No request, no token; nothing is written outside the scratch folder.

  1. Huntress CTF 2024 "Ancient Fossil" (the file as delivered): the flag of the write-up.
  2. Huntress CTF 2024 "Nightmare on Hunt Street" parts 1 and 2, from the XML export of Security.evtx
     (the .evtx itself is the `windows` toolkit's; this is the exported form `edr_persistence` reads).
  3. OTRF's CloudTrail of an S3 exfiltration, with questions in this event's style.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

sys.path.insert(0, str(rd.REPO / "tests"))
import toolkit_fixtures as tf   # noqa: E402

R = rd.Run("drills_b")
DRILLS = [
    {"name": "ancient-fossil", "file": "sqlite_artifacts/ctf2024_ancient_fossil/ancient.fossil", "as": "ancient.fossil", "toolkit": "sqlite_artifacts",
     "questions": [("fossil-flag", "What is the flag?", ("pick", "flag{2ed33f365669ea9f10b1a4ea4566fe8c}"))]},
    {"name": "nightmare-on-hunt-street", "file": "edr_persistence/ctf2024_nightmare/logs-parts1-5.zip.d/Security.evtx.xml", "as": "Security.xml",
     "toolkit": "edr_persistence",
     "questions": [("part-1", "What is the IP address of the host that the attacker used?", ("plain", "10.1.1.42")),
                   ("part-2", "How many times was the compromised account brute-forced? Answer just the integer value.", ("pick", "32")),
                   ("part-3", "What is the name of the offensive security tool that was used to gain initial access? Answer in all lowercase.", ("none", None)),
                   ("part-5", "What password was successfully given to the user created?", ("none", None))]},
    {"name": "s3-exfiltration", "file": "cloudlogs/otrf/ec2_proxy_s3_exfiltration.zip.d", "as": "cloudtrail.json", "toolkit": "cloud_container",
     "also": ("cloudlogs",),
     "questions": [("object", "Which object was downloaded from the S3 bucket?", ("plain", "ring.txt")),
                   ("bucket", "Which bucket was the object downloaded from?", ("plain", "mordors3stack-s3bucket-llp2yingx64a")),
                   ("key", "What access key ID was used for the GetObject requests?", ("plain", "ASIA5FLZVX4OPVKKVBMX")),
                   ("attacker", "What is the attacker's IP address?", ("notplain", None))]},
]


def main() -> int:
    if not rd.CACHE.is_dir():
        print(f"SKIP tests/real drills_b: no cache under {rd.CACHE} (run tests/real/fetch_b.py)")
        return 0
    scratch = Path(tempfile.mkdtemp(prefix="huntress-real-b-drill-"))
    env = dict(os.environ, CTF_WORKDIR=str(scratch), CTF_PLATFORM_URL="http://127.0.0.1:9/", CTF_TESTING="1")
    env.pop("CTF_TOKEN", None)
    try:
        for d in DRILLS:
            if not R.need(d["name"], d["file"]):
                continue
            src = rd.CACHE / d["file"]
            src = next(src.glob("*")) if src.is_dir() else src
            case = {"filename": d["as"], "data": src.read_bytes(), "name": d["name"], "key": {}, "toolkit": d["toolkit"],
                    "questions": [tf._q(qid, text, d["as"]) for qid, text, _ in d["questions"]]}
            folder = tf.write_attempt(scratch / "day-99" / d["name"], case)
            got = R.timed(f"{d['name']}: triage.py", lambda: subprocess.run([sys.executable, str(rd.REPO / "solvers" / "common" / "triage.py"), str(folder), "--quiet"],
                                                                          capture_output=True, text=True, env=env, timeout=110), limit=20.0)
            R.check(f"{d['name']}: triage wrote its map", got.returncode == 0 and (folder / "triage.md").is_file(), (got.stdout + got.stderr)[-300:])
            md = (folder / "triage.md").read_text() if (folder / "triage.md").is_file() else ""
            section = md.split("## Toolkits", 1)[1] if "## Toolkits" in md else ""
            named = re.findall(r"`(\w+)`|\b(\w+) signal", section)
            order = [a or b for a, b in named if (a or b) in ("sqlite_artifacts", "edr_persistence", "cloud_container", "cloudlogs", "nix_host", "windows",
                                                              "evidence_core", "repo_supply_chain", "web_evidence", "carve_stego", "network", "memory")]
            R.check(f"{d['name']}: the map names `{d['toolkit']}` among its toolkits", d["toolkit"] in order or any(a in order for a in d.get("also", ())), order[:6])
            mod = rd.toolkit(d["toolkit"])
            fs = {d["as"]: case["data"]}
            ans = R.timed(f"{d['name']}: {d['toolkit']}.solve_set", lambda: mod.solve_set(
                [{"qid": q["id"], "answer_id": q["id"], "question": q["question"], "answer_format": q.get("answer_format")} for q in case["questions"]], fs, {}))
            for qid, text, (how, want) in d["questions"]:
                a = ans.get(qid)
                ok = {"plain": a == want, "pick": want in [str(v) for v in rd.options(a)], "none": a is None, "notplain": not rd.plain(a)}[how]
                R.check(f"{d['name']}: {qid} is {how}" + (f" {want!r}" if want else ""), ok, repr(a)[:160])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
