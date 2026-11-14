"""The real-data tests (carried from Huntress tests/real) as pytest items.

Each tests/real/test_*.py is a script: it prints one `ok` / `FAIL` / `SKIP` line per check and exits 1
on any FAIL (run it by hand with `python tests/real/<name>.py`). Imported by pytest it would run at
collection and `sys.exit`, so pytest never imports it: this file collects each script as up to three
items, each running the script in a child Python and judging its output:

  <script>::realdata   with the corpus (ctf.paths.realdata_root(), i.e. CTF_REALDATA). Marked
                       needs_realdata(<kit>) for every corpus folder it reads, so without the corpus it
                       is NOT RUN, never green. With it, every check must have run: a SKIP line (a file
                       missing from a kit folder that is there) fails the item, as does any FAIL.
  <script>::synthetic  for a script that also has checks built in memory: run with CTF_REALDATA at an
                       empty folder, so those checks gate every run, corpus or not. SKIP lines are the
                       corpus checks and are expected here (the realdata item owns them).
  <script>::live       for a script with a HUNTRESS_TK_LIVE=1 section (it compares against tshark,
                       olevba or Volatility in the Docker sandbox). Marked live: never run by default.

KNOWN failures: a FAIL whose label matches a SCRIPTS[...].known_fail pattern does not fail the item; it
is reported in the NOT RUN list as `known-fail: <reason>` (and fails a CTF_STRICT_TESTS=1 run). Each one
is an engine regression or a missing carried piece that another unit owns; the reason names it. A new
FAIL fails the item.

Every script in this folder must be listed in SCRIPTS (an unlisted one is a collection error). The
child gets a minimal environment: no token, cookie or platform URL, a temporary CTF_WORKDIR, and never
HUNTRESS_TK_LIVE outside the live item. The corpus is untrusted data: the scripts read its bytes and run
nothing from it (no corpus binary is executed; the CLIs they call are this repo's own readers).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ctf import paths
from ctf.testing.pytest_plugin import record_not_run

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TIMEOUT = 280            # under the suite's --timeout 300

GM = ("triage.load_offline calls gm.artifact_path, and the Huntress Game Master module is not in the master "
      "(gm is None): the drill's offline attempt layout is unported (B-240 carry checklist)")
LANE = "tools/lane_match.py is archived (docs/migration/ARCHIVED.md), so the drill's winner check cannot run (B-240)"


@dataclass(frozen=True)
class Script:
    kits: tuple = ()          # corpus folders under the realdata root this script reads
    synthetic: bool = False   # it also has checks that need no corpus
    live: bool = False        # it has a HUNTRESS_TK_LIVE=1 (Docker sandbox) section
    args: tuple = ()
    slow: bool = False
    known_fail: tuple = ()    # ((regex on the FAIL line, reason), ...)
    tools: tuple = ()         # needs_tool names (e.g. "py:scapy") every item of the script needs


SCRIPTS = {
    "test_fixes_a.py": Script(synthetic=True),
    "test_review_a.py": Script(kits=("maldoc", "windows"), synthetic=True),
    "test_real_agent_trace.py": Script(kits=("agent_trace",)),
    "test_real_ai_model_files.py": Script(kits=("ai_model_files",)),
    "test_real_cab.py": Script(kits=("cab",), args=("-v",)),
    # R-15 fixed the CSCTF lsb_deep_scan cost (per-pixel loops) behind its CPU, stg300 and
    # flower_rgb1 known failures; its answer checks no longer depend on the wall clock.
    "test_real_carve_stego.py": Script(kits=("carve_stego",), synthetic=True),
    "test_real_classical.py": Script(kits=("classical",), synthetic=True),
    "test_real_cloud_container.py": Script(kits=("cloud_container", "cloudlogs")),
    "test_real_cloudlogs.py": Script(kits=("cloudlogs",)),
    "test_real_drill_a.py": Script(kits=("network", "windows", "email"), known_fail=(
        (r"the map is written and names `\w+` among its first two toolkits", GM),
        (r"lane_match picks toolkit:", LANE),
        (r"Nightmare on Hunt Street: the 4625 count of question 2 is offered", LANE),
    )),
    "test_real_drills_b.py": Script(
        kits=("sqlite_artifacts", "edr_persistence", "cloudlogs", "cloud_container", "nix_host", "windows",
              "memory", "network"),
        known_fail=((r"triage wrote its map", GM), (r"the map names `\w+` among its toolkits", GM))),
    "test_real_drills_d.py": Script(kits=("repo_supply_chain", "agent_trace", "classical"), known_fail=(
        (r"triage writes the map and its Toolkits section names", GM),
        (r"no lane solver claims it, and toolkit:\w+ answers the question", GM),
        (r"lane_match's winner is toolkit:", LANE),
        (r"drills? ran to (its|their) end", GM),
    )),
    "test_real_edr_persistence.py": Script(kits=("edr_persistence",)),
    "test_real_email.py": Script(kits=("email",)),
    "test_real_evidence_core.py": Script(kits=("evidence_core",), known_fail=(
        (r"drill: with HUNTRESS_BUNDLE_ROUTER=off the six questions stay None",
         "engine regression: with the bundle router off, the evidence_core layer still answers (or answers "
         "differently): the registry/bundle routing the B-001 brief calls silently off"),
    )),
    "test_real_evtx_header.py": Script(kits=("windows",)),
    "test_real_malconfig.py": Script(kits=("malconfig",), synthetic=True),
    "test_real_maldoc.py": Script(kits=("maldoc",), live=True),
    "test_real_memory.py": Script(kits=("memory",), synthetic=True, live=True),
    "test_real_modern_crypto.py": Script(kits=("modern_crypto",), synthetic=True),
    "test_real_network.py": Script(kits=("network",), live=True),
    "test_real_nix_host.py": Script(kits=("nix_host",)),
    # B-204: per-protocol OT oracle. kits=("ot",) so it runs when any OT corpus is present; the
    # synthetic section (built fixtures) gates every run. scapy reads the pcaps.
    "test_real_ot.py": Script(kits=("ot",), synthetic=True, tools=("py:scapy",)),
    "test_real_repo_supply_chain.py": Script(kits=("repo_supply_chain",)),
    "test_real_review_b.py": Script(kits=("cloud_container", "cloudlogs", "edr_persistence", "nix_host",
                                          "sqlite_artifacts"), synthetic=True),
    "test_real_rf.py": Script(kits=("rf",), synthetic=True),
    "test_real_sqlite_artifacts.py": Script(kits=("sqlite_artifacts",)),
    "test_real_web.py": Script(kits=("web_evidence",), synthetic=True),
    "test_real_web_evidence.py": Script(kits=("web_evidence",)),
    "test_real_windows.py": Script(kits=("windows",), slow=True),
}

# Token shapes the commit guard blocks: never echoed from a child's output into a report.
_SECRET = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b|\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}"
                     r"|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bctfd_[a-f0-9]{64}\b")
_LINE = re.compile(r"^(ok|FAIL|SKIP)\b\s*(.*)$")
_DETAIL = re.compile(r"\s{2,}\[.*$", re.S)    # a check line's "  [detail]" tail
_LIVE_DOWN = re.compile(r"sandbox down|live \w+ run is skipped|did not run", re.I)


def scrub(text: str) -> str:
    return _SECRET.sub(lambda m: (m.group(1) or m.group(0)[:4]) + "<redacted>", text)


def parse(out: str) -> dict:
    got = {"ok": [], "FAIL": [], "SKIP": []}
    for line in out.splitlines():
        m = _LINE.match(line)
        if m:
            got[m.group(1)].append(m.group(2).strip())
    return got


def child_env(corpus: Path, workdir: Path, live: bool) -> dict:
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "USER", "LOGNAME", "SHELL", "CTF_EVENT")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE="1", CTF_REALDATA=str(corpus),
               CTF_WORKDIR=str(workdir), CTF_TESTING="1", CSCTF_TESTING="1", HUNTRESS_TESTING="1",
               PYTHONWARNINGS="ignore::DeprecationWarning")
    if live:
        env["HUNTRESS_TK_LIVE"] = "1"
    return env


def verdict(spec: Script, mode: str, code: int, out: str) -> dict:
    """Judge one run of a script from its exit code and output. Returns {problems, new, known, skip, ok}:
    the item fails when `problems` is not empty; `known` are FAIL lines matching spec.known_fail."""
    lines = parse(out)
    known, new = [], []
    for label in lines["FAIL"]:
        hit = next((reason for rx, reason in spec.known_fail if re.search(rx, label)), None)
        if hit:
            known.append((label, hit))
        else:
            new.append(label)
    problems = []
    if new:
        problems.append(f"{len(new)} check(s) FAILED")
    if code not in (0, 1) or (code == 1 and not lines["FAIL"]) or (code == 0 and lines["FAIL"]):
        problems.append(f"exit {code} does not match {len(lines['FAIL'])} FAIL line(s) (a crash?)")
    if not lines["ok"]:
        problems.append("no check ran (0 ok lines)")
    if mode in ("realdata", "live") and lines["SKIP"]:
        # the SKIP lines name their own cause (a file missing or differing from the manifest, or a cost limit
        # with no work meter), so the problem quotes them rather than guessing one
        reasons = "; ".join(lines["SKIP"][:3]) + ("; ..." if len(lines["SKIP"]) > 3 else "")
        problems.append(f"the corpus is present but {len(lines['SKIP'])} check group(s) SKIPped: {reasons}")
    if mode == "live" and _LIVE_DOWN.search(out):
        problems.append("the live comparison did not run (sandbox down or no symbol pack)")
    return {"problems": problems, "new": new, "known": known, "skip": lines["SKIP"], "ok": len(lines["ok"])}


class ScriptFailed(Exception):
    pass


class RealScriptItem(pytest.Item):
    def __init__(self, *, mode: str, spec: Script, **kw):
        super().__init__(**kw)
        self.mode, self.spec = mode, spec

    def runtest(self):
        with tempfile.TemporaryDirectory(prefix="ctf-real-") as td:
            td = Path(td)
            if self.mode == "synthetic":
                corpus = td / "empty-corpus"
                corpus.mkdir()
            else:
                corpus = paths.realdata_root()
            work = td / "work"
            work.mkdir()
            try:
                r = subprocess.run([sys.executable, str(self.path), *self.spec.args], cwd=str(td),
                                   env=child_env(corpus, work, self.mode == "live"),
                                   capture_output=True, text=True, timeout=TIMEOUT)
            except subprocess.TimeoutExpired as e:
                raise ScriptFailed(f"{self.path.name} did not finish in {TIMEOUT} s\n"
                                   + scrub((e.stdout or b"")[-2000:].decode("utf-8", "replace")
                                           if isinstance(e.stdout, bytes) else (e.stdout or "")[-2000:]))
        self.judge(r.returncode, scrub(r.stdout), scrub(r.stderr))

    def judge(self, code: int, out: str, err: str) -> None:
        v = verdict(self.spec, self.mode, code, out)
        for label, reason in v["known"]:
            record_not_run(self, _DETAIL.sub("", label)[:160], f"known-fail: {reason}")
        self.user_properties.append(("ctf_checks", v["ok"]))
        if v["problems"]:
            body = ["; ".join(v["problems"]), ""]
            body += [f"FAIL {label[:600]}" for label in v["new"]]
            if self.mode in ("realdata", "live"):
                body += [f"SKIP {s}" for s in v["skip"]]
            body += [f"(ok: {v['ok']}, known failures: {len(v['known'])})", "--- stderr (tail) ---",
                     *err.splitlines()[-15:]]
            raise ScriptFailed("\n".join(body))

    def repr_failure(self, excinfo, style=None):
        if isinstance(excinfo.value, ScriptFailed):
            return f"{self.path.name} ({self.mode}): {excinfo.value}"
        return super().repr_failure(excinfo, style)

    def reportinfo(self):
        return self.path, None, f"{self.path.name}::{self.mode}"


class RealScriptFile(pytest.File):
    def collect(self):
        spec = SCRIPTS.get(self.path.name)
        if spec is None:
            raise self.CollectError(f"{self.path.name} is not listed in tests/real/conftest.py SCRIPTS: "
                                    f"say which corpus folders it reads")
        def with_tools(item):
            for tool in spec.tools:
                item.add_marker(pytest.mark.needs_tool(tool))
            return item

        if spec.kits:
            item = RealScriptItem.from_parent(self, name="realdata", mode="realdata", spec=spec)
            for kit in spec.kits:
                item.add_marker(pytest.mark.needs_realdata(kit))
            if spec.slow:
                item.add_marker(pytest.mark.slow)
            yield with_tools(item)
        if spec.synthetic or not spec.kits:
            yield with_tools(RealScriptItem.from_parent(self, name="synthetic", mode="synthetic", spec=spec))
        if spec.live:
            item = RealScriptItem.from_parent(self, name="live", mode="live", spec=spec)
            item.add_marker(pytest.mark.live)
            for kit in spec.kits:
                item.add_marker(pytest.mark.needs_realdata(kit))
            yield with_tools(item)


def pytest_pycollect_makemodule(module_path, parent):
    if module_path.parent == HERE and module_path.name.startswith("test_"):
        return RealScriptFile.from_parent(parent, path=module_path)
    return None
