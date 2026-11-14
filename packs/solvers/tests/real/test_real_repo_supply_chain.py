#!/usr/bin/env python3
"""The toolkit repo_supply_chain on real repositories and packages (docs/toolkits/real-data.md).

  .venv/bin/python tests/real/test_real_repo_supply_chain.py

SKIPs (exit 0) when challenges/_realdata/repo_supply_chain is not there; tests/real/fetch_d.py
fills it. The files: two Huntress challenges whose flag the write-up states (2024 Ancient Fossil,
a Fossil repository; 2025 Darcy, a darcs repository), the 2024 Backdoored Splunk II app, a real
git clone with fake secrets in its history (trufflesecurity/test_keys: the commits asserted here
are the ones the GitHub API lists), and packages from PyPI, npm, RubyGems, Maven Central, NuGet,
Open VSX and the Chrome Web Store. The independent readers are sqlite3 (Fossil's event table),
gzip and a regular expression (darcs' inventory), hashlib (the Splunk manifest) and zipfile and
tarfile (the packages). No git, hg, darcs, fossil, npm or pip is run, and nothing is installed.
"""
import gzip
import hashlib
import io
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common_d as C                    # noqa: E402
from common_d import check, q, opts     # noqa: E402

sys.path.append(str(C.REPO / "tests"))      # last, so tests/ shadows no toolkit module
import sh09_clocks                      # noqa: E402

NO_METER = None


def timed(fn, *a, **k):
    """(fn(*a), its work in seconds at the core's top clock), not (fn(*a), wall seconds) as common_d.timed
    gives. Core cycles over the top clock (tests/sh09_clocks.work_seconds): under the suite's sustained
    load (50-170 on 14 cores, SH-09/SH-10) this laptop clocks its cores down to about half their top speed,
    so the same parse costs about twice the wall or CPU seconds it costs on an idle machine, and a bound set
    on an idle machine flakes (repo_supply_chain's 2 s limit is the case, per the SH-11 brief). Work is the
    idle-machine cost, which a lower clock does not change. The toolkit runs no git/hg/darcs/npm/pip here, so
    its own cycles are its whole work. Without the meter the work is None (the answer checks still run) and
    main() reports the cost bound not run (a SKIP), never passed."""
    global NO_METER
    out, work, why = sh09_clocks.work_seconds_unless_missing(fn, *a, **k)
    if why:
        NO_METER = why
    return out, work


KIT = "repo_supply_chain"
D = C.fetch_d.have(KIT)
if D is None:
    sys.exit(C.fetch_d.skip("tests/real/test_real_repo_supply_chain.py", KIT))
T = C.toolkit(KIT)
SLOW = []
FOSSIL_FLAG = "flag{2ed33f365669ea9f10b1a4ea4566fe8c}"        # Huntress-CTF-2024/forensics/ancient_fossil_COMPLETED/flag.txt
DARCY_FLAG = "flag{a0c1e852e1281d134f0ac2b8615183a3}"         # CTF-Huntress_2025/day20/1_Darcy_COMPLETED.md


def files_of(name: str) -> dict:
    p = D / name
    if p.is_dir():
        return {str(f.relative_to(p.parent)): f.read_bytes() for f in sorted(p.rglob("*")) if f.is_file()}
    out = {}
    C.run.expand(p.name, p.read_bytes(), out)
    return out


def ask(name, *questions, files=None):
    files = files if files is not None else files_of(name)
    got, took = timed(T.solve_set, list(questions), files, {})
    if took is not None and took > 2.0:
        SLOW.append((name, round(took, 2)))
    return [got[x["qid"]] for x in questions]


def analysis(name):
    (A, took) = timed(lambda: T.Analysis(files_of(name)))
    if took is not None and took > 2.0:
        SLOW.append((name + " analysis", round(took, 2)))
    return A


def secrets(A, kind):
    return [s for s in A.secrets if s["kind"] == kind]


# ---- the two challenges with a known flag ----------------------------------------------------------------------

def test_ancient_fossil():
    A = analysis("ancient.fossil")
    h = A.histories[0]
    con = sqlite3.connect(f"file:{D / 'ancient.fossil'}?mode=ro&immutable=1", uri=True)
    checkins = con.execute("SELECT count(*) FROM event WHERE type='ci'").fetchone()[0]
    con.close()
    check("2024 Ancient Fossil: a Fossil history with as many check-ins as its own event table counts (403)",
          h.kind == "fossil" and len(list(h.ids())) == checkins == 403, (h.kind, len(list(h.ids())), checkins))
    flags = secrets(A, "flag")
    check("2024 Ancient Fossil: the write-up's flag is the one flag in the history, with its check-in",
          [s["value"] for s in flags] == [FOSSIL_FLAG] and flags[0]["where"][0]["commit"].startswith("5c1d602e0e22"), flags)
    a = ask("ancient.fossil", q("flag", "What is the flag hidden in the repository history?", member="ancient.fossil"),
            q("commit", "Which commit added the flag?", member="ancient.fossil"),
            q("n", "How many check-ins does the repository have?", "integer", "ancient.fossil"),
            q("author", "Who is the author of the commit that added the flag?", member="ancient.fossil"))
    check("2024 Ancient Fossil: end to end, the flag is the answer offered (unsure: nothing of this category is judged)",
          opts(a[0]) == {"value": FOSSIL_FLAG}, a[0])
    check("2024 Ancient Fossil: the check-in, the count with and without Fossil's empty first check-in, the author",
          (opts(a[1]) or {}).get("full", "").startswith("5c1d602e0e2208eed33bfa98") and opts(a[2]) == {"all": "403", "without_empty_first": "402"}
          and opts(a[3]) == {"name": "kali"}, a[1:])


def test_darcy():
    A = analysis("darcy")
    h = A.histories[0]
    inv = (D / "darcy" / "_darcs" / "hashed_inventory").read_bytes()
    inv = gzip.decompress(inv) if inv[:2] == b"\x1f\x8b" else inv
    names = re.findall(rb"(?m)^\[(.*)\n.*?\*\*\d{14}", inv)
    check("2025 Darcy: a darcs history with as many patches as its inventory lists (402)",
          h.kind == "darcs" and len(list(h.ids())) == len(names) == 402, (h.kind, len(list(h.ids())), len(names)))
    check("2025 Darcy: the inventory's one patch name with a flag is the write-up's flag",
          [n.decode() for n in names if b"flag{" in n] == ["routine update; details: " + DARCY_FLAG])
    flags = secrets(A, "flag")
    check("2025 Darcy: the flag is found in a commit message", [s["value"] for s in flags] == [DARCY_FLAG]
          and any(w.get("state") == "commit message" for w in flags[0]["where"]), flags)
    files = files_of("darcy")
    a = ask("darcy", q("flag", "What is the flag hidden in the repository history?", member="darcy"),
            q("patch", "Which patch holds the flag?", member="darcy"),
            q("n", "How many patches does the repository have?", "integer", "darcy"),
            q("email", "What is the author e-mail of the commit that leaked the flag?", member="darcy"),
            q("msg", "What is the commit message of the commit that holds the flag?", member="darcy"), files=files)
    check("2025 Darcy: end to end, the flag is the answer offered", opts(a[0]) == {"value": DARCY_FLAG}, a[0])
    check("2025 Darcy: a secret in a commit message names its commit: the patch, its author and its message",
          (opts(a[1]) or {}).get("name") == "routine update; details: " + DARCY_FLAG and opts(a[2]) == {"all": "402"}
          and opts(a[3]) == {"email": "ctf@ctf.huntress.com"} and (opts(a[4]) or {}).get("subject") == "routine update; details: " + DARCY_FLAG, a[1:])
    rows = [{"id": c, "when": "", "message": h.meta(c).get("message") or ""} for c in h.ids()]
    odd = [c["message"] for c in T.unusual_messages(rows)]
    check("2025 Darcy: of 402 generated messages the two unlike the others are named, the flag's among them",
          len(odd) <= 3 and any(DARCY_FLAG in m for m in odd), odd)
    check("2025 Darcy: the signal reaches the toolkit's threshold for a darcs delivery", T.signals(
        [q("flag", "What is the flag hidden in the repository history?", member="darcy")], files) >= 0.6)


def test_splunk_app():
    name = "Splunk_TA_windows.zip"
    z = zipfile.ZipFile(D / name)
    man = json.loads(z.read("Splunk_TA_windows/splunkbase.manifest"))
    bad = sorted(e["path"] for e in man["app"]["files"] if hashlib.sha256(z.read("Splunk_TA_windows/" + e["path"])).hexdigest() != e["hash"])
    A = analysis(name)
    pk = [p for p in A.packages if p["kind"] == "hash_manifest"]
    check("2024 Backdoored Splunk II: the app's own hash manifest is checked: 75 rows, the three files hashlib also finds changed",
          len(pk) == 1 and pk[0]["record"]["rows"] == 75 and sorted(r["path"] for r in pk[0]["record"]["mismatched"]) == bad ==
          ["bin/powershell/dns-health.ps1", "bin/runpowershell.cmd", "default/inputs.conf"], pk and pk[0]["record"]["mismatched"])
    a = ask(name, q("n", "How many files fail the manifest's integrity check?", "integer", name),
            q("file", "Which file of the app was backdoored?", member=name))
    check("2024 Backdoored Splunk II: the count is offered; which of three changed files is the backdoor is not chosen",
          opts(a[0]) == {"mismatched": "3"} and a[1] is None, a)


# ---- a real git clone ------------------------------------------------------------------------------------------

# The six commits of main as https://api.github.com/repos/trufflesecurity/test_keys/commits lists them (2026-10-08)
# and the one of origin/add-README: (id prefix, author e-mail, first line of the message)
API = [("fbc14303ffbf", "counter@counters-MacBook-Air.local", "doing some dev work"), ("742a554281e8", "counter@counters-MacBook-Air.local", "woops, some keys"),
       ("77b2a3e56973", "counter@counters-MacBook-Air.local", "adding stuff"), ("7faa1b622a2e", "8292703+hxnyk@users.noreply.github.com", "add package.json"),
       ("1fc0463f2fc2", "8292703+hxnyk@users.noreply.github.com", "Merge pull request #2 from trufflesecurity/npm"),
       ("0416560b1330", "hello@trufflesec.com", "adding a key")]


def test_git_clone():
    A = analysis("test_keys")
    g = A.histories[0]
    rows = {c["id"][:12]: (c["email"], c["message"].split("\n")[0]) for c in g.table()}
    check("git: every commit of main as the GitHub API lists it (id, e-mail, message), read from the pack with no git binary",
          g.kind == "git" and all(rows.get(i) == (e, m) for i, e, m in API), {i: rows.get(i) for i, _, _ in API})
    check("git: seven commits in all (the seventh is on origin/add-README), HEAD on main", len(rows) == 7 and g.head()["ref"] == "refs/heads/main"
          and g.head()["id"].startswith("0416560b1330"), (len(rows), g.head()))
    keys = sorted(s["value"] for s in secrets(A, "aws_access_key_id"))
    key_digests = {hashlib.sha256(k.encode()).hexdigest() for k in keys}   # the key ids are pinned by SHA-256 (commit guard)
    check("git: the AWS key id that only the first commit holds is found in history, beside the one still in the tree",
          "bf838ec22b2e1e6cfd50c7c3d20c53956728be21db1be3e3a5f102db4163b0ef" in key_digests and "53de5baa315bb91d8915f039f7cd3514f4b042a08ae1036a8298d954cdc069f0" in key_digests, sorted(key_digests))
    a = ask("test_keys", q("n", "How many commits does the repository have?", "integer", "test_keys"),
            q("remote", "What is the remote URL of the repository?", member="test_keys"),
            q("branch", "What is the current branch?", member="test_keys"),
            q("akid", "Which AWS access key id was leaked in the repository?", member="test_keys"))
    check("git: the commit count is offered both ways (6 from HEAD, 7 from every ref); remote and branch",
          opts(a[0]) == {"reachable_from_head": "6", "reachable_from_refs": "7"} and opts(a[1]) == {"url": "https://github.com/trufflesecurity/test_keys"}
          and opts(a[2]) == {"name": "main"}, a[:3])
    check("git: several AWS key ids in the delivery: none is chosen", a[3] is None, a[3])


# ---- real packages ---------------------------------------------------------------------------------------------

def pkg(name, kind=None):
    A = analysis(name)
    got = [p for p in A.packages if kind is None or p["kind"] == kind]
    return got[0] if got else None


def test_packages():
    n = "setuptools-68.0.0-py3-none-any.whl"
    z = zipfile.ZipFile(D / n)
    empty = [i.filename for i in z.infolist() if i.file_size == 0]
    p = pkg(n, "wheel")
    rec = p["record"]
    check("wheel: setuptools 68.0.0, RECORD's 235 rows all verify: the four empty members are four files, none missing",
          (p["name"], p["version"]) == ("setuptools", "68.0.0") and len(empty) == 4 and rec["rows"] == 235 and not rec["mismatched"]
          and not rec["missing"] and not rec["unlisted"], (rec["rows"], rec["missing"], rec["unlisted"]))
    line = z.read("distutils-precedence.pth").decode().strip()
    a = ask(n, q("pth", "Which .pth file does the wheel install?", member=n), q("line", "What line does the .pth file execute at every Python start?", member=n),
            q("bad", "How many files of the wheel fail RECORD verification?", "integer", n))
    check("wheel: the real .pth file and the line it runs; no file fails RECORD",
          opts(a[0]) == {"path": "distutils-precedence.pth"} and opts(a[1]) == {"line": line} and opts(a[2]) == {"mismatched": "0"}, a)
    p = pkg("six-1.16.0-py2.py3-none-any.whl", "wheel")
    check("wheel: six 1.16.0, six rows, clean", (p["name"], p["version"], p["record"]["rows"], p["record"]["mismatched"]) == ("six", "1.16.0", 6, []))
    p = pkg("six-1.16.0.tar.gz", "sdist")
    check("sdist: six 1.16.0", p is not None and (p["name"], p["version"]) == ("six", "1.16.0"), p and (p["name"], p["version"]))

    n = "husky-4.3.8.tgz"
    with tarfile.open(D / n) as tf:
        scripts = json.load(tf.extractfile("package/package.json"))["scripts"]
    p = pkg(n, "npm")
    hooks = {h["when"]: h["command"] for h in p["hooks"] if h.get("install_time")}
    check("npm: husky 4.3.8, its two install-time hooks exactly as package.json has them",
          (p["name"], p["version"]) == ("husky", "4.3.8") and hooks == {"install": scripts["install"], "postinstall": scripts["postinstall"]}, hooks)
    a = ask(n, q("cmd", "What command does the postinstall hook of the npm package run?", member=n), q("name", "What is the name of the npm package?", member=n))
    check("npm: the postinstall command and the package name", opts(a[0]) == {"command": "opencollective-postinstall || exit 0"} and opts(a[1]) == {"name": "husky"}, a)
    p = pkg("left-pad-1.3.0.tgz", "npm")
    check("npm: left-pad 1.3.0 has no install-time hook", (p["name"], p["version"]) == ("left-pad", "1.3.0") and not any(h.get("install_time") for h in p["hooks"]))

    p = pkg("google-docs-offline.crx", "crx")
    check("crx: the extension id derived from the signed header is the Web Store id the file was fetched by; the name is the locale's message",
          p["extension_id"] == "ghbmnnjooekpmoecnnnilnnbdlolhkhi" and p["name"] == "Google Docs Offline" and p["name_in_manifest"] == "__MSG_extName__",
          (p["extension_id"], p["name"]))
    p = pkg("ant-launcher-1.10.14.jar", "jar")
    check("jar: the Main-Class of MANIFEST.MF", p["entry"] == "org.apache.tools.ant.launch.Launcher", p["entry"])
    p = pkg("jquery.1.9.1.nupkg", "nupkg")
    check("nupkg: jQuery 1.9.1, Tools/install.ps1 runs at install", (p["name"], p["version"]) == ("jQuery", "1.9.1")
          and any(h.get("install_time") and "install.ps1" in h["where"] for h in p["hooks"]), p["hooks"])
    p = pkg("rake-13.0.6.gem", "gem")
    check("gem: rake 13.0.6", (p["name"], str(p["version"])) == ("rake", "13.0.6"), (p["name"], p["version"]))
    p = pkg("editorconfig-0.18.2.vsix", "vsix")
    check("vsix: EditorConfig 0.18.2, its entry file", (p["name"], p["version"]) == ("EditorConfig", "0.18.2") and p["entry"] == "./out/editorConfigMain.js", p["entry"])
    p = pkg("labeler-workflow.yml", "github_workflow")
    check("workflow: a lone YAML file with `on` and `jobs` is read as one; pull_request_target and two unpinned actions",
          p is not None and p["triggers"] == ["pull_request_target"] and len(p["uses"]) == 2, p and (p["triggers"], p["uses"]))


def test_cli():
    tmp = Path(tempfile.mkdtemp(prefix="test_real_rsc_"))
    try:
        out = subprocess.run([sys.executable, str(C.REPO / "solvers" / "toolkits" / "repo_supply_chain.py"), str(D / "darcy")],
                             capture_output=True, text=True, timeout=120, cwd=tmp)
        check("the command on the darcs repository: exit 0, the cut is said, the odd message and the flag are on the page",
              out.returncode == 0 and "more commits not shown" in out.stdout and "UNUSUAL MESSAGE" in out.stdout and DARCY_FLAG in out.stdout,
              out.stdout[-300:] + out.stderr[-200:])
        out = subprocess.run([sys.executable, str(C.REPO / "solvers" / "toolkits" / "repo_supply_chain.py"), str(D / "Splunk_TA_windows.zip")],
                             capture_output=True, text=True, timeout=120, cwd=tmp)
        check("the command on the Splunk app: the three MANIFEST MISMATCH lines", out.stdout.count("MANIFEST MISMATCH") == 3, out.stdout[:300])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    for t in (test_ancient_fossil, test_darcy, test_splunk_app, test_git_clone, test_packages, test_cli):
        try:
            t()
        except Exception as e:      # noqa: BLE001 - a crash on a real file is the finding
            check(f"{t.__name__} ran to its end", False, f"{type(e).__name__}: {e}")
    # The 2 s limit is an idle-machine work bound (seconds at the core's top clock), not wall time, so it
    # holds under load (rule 16, SH-11). Without the work meter the bound is reported not run, never passed.
    if NO_METER:
        print(f"SKIP cost bound: no file is held to its 2 s work limit: no work meter ({NO_METER})")
    else:
        check("no file took the toolkit more than 2 s of work", not SLOW, SLOW)
    return C.finish("tests/real/test_real_repo_supply_chain.py")


if __name__ == "__main__":
    sys.exit(main())
