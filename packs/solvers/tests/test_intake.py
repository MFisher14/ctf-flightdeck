"""Parallel no-model intake per challenge (B-002): plan, engine runs, one intake, many in parallel, CLI.

Every handout is built here; every engine is a script this test writes into a throwaway checkout (the
real ctf package symlinked in). The platform is a fake adapter object or the manual drop folder; no
network is used except loopback listeners the test owns.
"""
from __future__ import annotations

import base64
import io
import json
import socket
import zipfile
from pathlib import Path

import pytest

from ctf import event, ledger, paths
from ctf.intake import engines as E
from ctf.intake import guard as G
from ctf import intake as I
from ctf.platform.base import Challenge, FileRef, PlatformError

REPO = paths.repo_root()
CSCTF = event.load("csctf")
SPOOKY = event.load("spooky")
HOOK = G.Guard("hook", (), "test: hook only")


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _engine(root, lane, name, code, *, entry=None, caps='["analysis", "cli", "legacy-output"]', extra="",
            intake=None, routes=""):
    _w(root, f"solvers/{lane}/{name}.py", code)
    entry = entry or f"cli:python solvers/{lane}/{name}.py"
    if "cost_class" not in extra:
        extra += '\ncost_class = "cheap"'
    text = (f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "{entry}"\ncapabilities = {caps}\n{extra}\n'
            + (f"[intake]\n{intake}\n" if intake else "") + routes)
    _w(root, f"solvers/{lane}/{name}.manifest.toml", text)


CATFLAG = """\
import os, sys
for p in sys.argv[1:]:
    print("FILE", os.path.basename(p))
    print(open(p, encoding="utf-8", errors="replace").read())
print("SECRET_ENV", sorted(k for k in os.environ if "TOKEN" in k or "COOKIE" in k))
print("EVENT", os.environ.get("CTF_EVENT"))
print("CWD", os.path.basename(os.getcwd()))
"""

SLEEPER = "import sys, time\ntime.sleep(float(open(sys.argv[1]).read().strip() or 1))\nprint('slept')\n"

NETPROBE = """\
import socket, sys
port = int(open(sys.argv[1]).read())
try:
    socket.create_connection(("127.0.0.1", port), timeout=2)
    print("CONNECTED")
except PermissionError as e:
    print("REFUSED", e)
"""

SPAWNER = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'print(1)'])\nprint('SPAWNED')\n"

JSONRES = """\
import sys
from ctf.result import SolverResult, Evidence
data = open(sys.argv[1]).read().strip()
print("working")
print(SolverResult("candidate", flags=[data], evidence=[Evidence("x", "y")]).to_json())
"""

CHOOSER = """\
from ctf.result import SolverResult, Evidence
print("noise CSCTF{stdout_decoy} noise")
print(SolverResult("candidate", flags=["CSCTF{the_chosen_one}"], evidence=[Evidence("x", "y")]).to_json())
"""

ERRCAT = "import sys\nsys.stderr.write(open(sys.argv[1]).read())\n"

FN_ENGINE = """\
from ctf.result import SolverResult, Evidence
def solve(challenge_dir, profile, **opts):
    marks = sorted(p.name for p in (challenge_dir / "unpacked").rglob("*.marker"))
    if not marks:
        return SolverResult("none", notes="no marker")
    return SolverResult("solved", flags=["CSCTF{from_function_" + str(len(marks)) + "}"],
                        evidence=[Evidence("x", marks[0])], notes=profile.slug)
"""


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "ctf").symlink_to(REPO / "ctf", target_is_directory=True)
    _engine(r, "toolkits", "catflag", CATFLAG,
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.txt"]\nmax_files = 2\n')
    _engine(r, "toolkits", "allcat", CATFLAG,
            intake='select = "files"\nrun = "all-files"\nmatch = ["ext:.cfg"]\nmax_files = 2\n')
    _engine(r, "toolkits", "sleeper", SLEEPER,
            intake='select = "files"\nrun = "per-file"\nmatch = ["name:*.slow"]\ntimeout = 2\n')
    _engine(r, "toolkits", "netprobe", NETPROBE,
            intake='select = "files"\nrun = "per-file"\nmatch = ["name:*.probe"]\n')
    _engine(r, "toolkits", "sneaky", SPAWNER,              # spawns but does not say so
            intake='select = "files"\nrun = "per-file"\nmatch = ["name:*.sneak"]\n')
    _engine(r, "toolkits", "spawner", SPAWNER,
            intake='select = "files"\nrun = "per-file"\nmatch = ["name:*.spawn"]\nspawns = true\n')
    _engine(r, "toolkits", "jsonres", JSONRES, caps='["analysis", "cli"]',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.res"]\n')
    _engine(r, "toolkits", "nojson", "import sys\nprint(open(sys.argv[1]).read())\n", caps='["analysis", "cli"]',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.nojson"]\n')
    _engine(r, "toolkits", "chooser", CHOOSER, caps='["analysis", "cli"]',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.pick"]\n')
    _engine(r, "toolkits", "errcat", ERRCAT,
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.errout"]\n')
    _engine(r, "web", "fn_engine", FN_ENGINE, entry="solvers.web.fn_engine:solve", caps='["executes"]',
            intake='run = "challenge"\n', routes='[[routes]]\ncategory = ["web"]\npriority = 70\n')
    _engine(r, "web", "routed_folder", CATFLAG, intake='run = "folder"\nargs = ["{folder}/x.txt"]\n',
            routes='[[routes]]\nkeywords = ["folderword"]\npriority = 60\n')
    _engine(r, "toolkits", "plain_routed", "print('hi')\n",
            routes='[[routes]]\ncategory = ["forensics"]\npriority = 55\n')
    _engine(r, "toolkits", "planner", "print('x')\n", caps='["plan"]', extra='status = "plan-only"',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.txt"]\n')
    _engine(r, "toolkits", "pricey", "print('x')\n", extra='cost_class = "heavy"',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.txt"]\n')
    _engine(r, "toolkits", "needy", "print('x')\n", extra='needs_tools = ["no-such-tool-b002", "py:no_such_mod_b002"]',
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.txt"]\n')
    _engine(r, "toolkits", "external", "", entry="cli:true",
            intake='select = "files"\nrun = "per-file"\nmatch = ["ext:.txt"]\n')
    return r


def _ms(root):
    from ctf.engines import manifest
    return manifest.discover(root)


class FakeAdapter:
    kind = "fake"

    def __init__(self, challenges: dict, fail_get=(), fail_download=()):
        self.challenges = challenges          # id -> (Challenge, {relpath: bytes})
        self.fail_get, self.fail_download = set(fail_get), set(fail_download)
        self.submits = []

    def list_challenges(self):
        return [c for c, _ in self.challenges.values()]

    def get_challenge(self, cid):
        if cid in self.fail_get or cid not in self.challenges:
            raise PlatformError(f"get_challenge({cid}): HTTP 404")
        return self.challenges[cid][0]

    def download_files(self, cid, dest):
        if cid in self.fail_download:
            raise PlatformError(f"download_files({cid}): HTTP 500")
        out = []
        for rel, data in self.challenges[cid][1].items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        self.submits.append((cid, flag))
        raise AssertionError("intake must never submit")

    def team_solves(self):
        return []

    def scoreboard(self):
        return []


def _ch(cid, name="Chal", category="misc", description="", points=100, solved=False, files=()):
    return Challenge(id=cid, name=name, category=category, points=points, description=description,
                     files=tuple(FileRef(f) for f in files), solved_by_team=solved)


def _zip(members: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in members.items():
            z.writestr(n, d)
    return b.getvalue()


def _opts(root, **kw):
    kw.setdefault("net_guard", "hook")
    return I.Options(root=root, **kw)


# ---------------------------------------------------------------- plan

def _heads(folder: Path, files: dict):
    for rel, data in files.items():
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return E.input_files(folder)


def test_plan_selects_by_file_route_and_says_why_it_skips(root, tmp_path):
    folder = tmp_path / "unpacked"
    _heads(folder, {"a.txt": b"one", "b.txt": b"two", "c.txt": b"three", "s.cfg": b"x", "t.cfg": b"y",
                    "u.cfg": b"z", ".sweep.json": b"{}", "deep/m.marker": b""})
    p = E.plan(_ms(root), "Web", "a challenge", folder, guard=HOOK)
    jobs = [(j.engine, tuple(f.name for f in j.files)) for j in p.jobs]
    assert jobs == [("web.fn_engine", ()),                                # routed by category, priority 70
                    ("toolkits.allcat", ("s.cfg", "t.cfg")),
                    ("toolkits.catflag", ("a.txt",)), ("toolkits.catflag", ("b.txt",))]
    skipped = {s.engine: s.reason for s in p.skipped}
    assert "1 more matching file(s) over its max_files = 2" in skipped["toolkits.catflag"]
    assert "1 matching file(s) left out" in skipped["toolkits.allcat"]
    assert skipped["toolkits.planner"].startswith("status plan-only")
    assert "cost_class heavy is over the intake cap cheap" in skipped["toolkits.pricey"]
    assert skipped["toolkits.needy"] == "needs no-such-tool-b002, py:no_such_mod_b002 (not installed)"
    assert "an external-command entry needs the OS network sandbox; test: hook only" == skipped["toolkits.external"]
    assert "web.routed_folder" not in skipped and "toolkits.sleeper" not in skipped   # not selected at all
    assert p.routed["web.fn_engine"][0] == 70
    assert not p.unadapted                                                 # plain_routed is forensics


def test_plan_raises_the_cost_cap_and_lists_routed_engines_without_an_adapter(root, tmp_path):
    folder = tmp_path / "unpacked"
    _heads(folder, {"a.txt": b"one"})
    p = E.plan(_ms(root), "forensics", "folderword here", folder, guard=HOOK, max_cost="heavy")
    ids = [j.engine for j in p.jobs]
    assert "toolkits.pricey" in ids and "web.routed_folder" in ids and "web.fn_engine" not in ids
    assert ("toolkits.plain_routed", 55, "category forensics") in p.unadapted
    with pytest.raises(ValueError, match="max_cost 'huge'"):
        E.plan(_ms(root), "web", "", folder, guard=HOOK, max_cost="huge")


def test_plan_spawning_engines_need_the_os_guard(root, tmp_path):
    folder = tmp_path / "unpacked"
    _heads(folder, {"x.spawn": b"", "y.txt": b""})
    hook = {s.engine: s.reason for s in E.plan(_ms(root), "misc", "", folder, guard=HOOK).skipped}
    assert hook["toolkits.spawner"] == "it starts other programs, and test: hook only"
    osg = G.Guard("os", ("sbx",), "os")
    p = E.plan(_ms(root), "misc", "", folder, guard=osg)
    ids = {j.engine for j in p.jobs}
    assert {"toolkits.spawner", "toolkits.external"} <= ids


def test_route_hits_rank_exactly_as_the_router_does(tmp_path):
    """Intake routes through the router's own ranking: on a folder without sweep files, route_hits over
    its heads gives the same engines, priorities, reasons and order as router.route, on the repo's
    real manifests plus synthetic ones with file routes, several routes and priority ties."""
    from ctf.engines import manifest, router
    syn = tmp_path / "syn"
    route = '[[routes]]\n{}\npriority = {}\n'
    _engine(syn, "toolkits", "png_magic", "", routes=route.format('files = ["magic:\\u0089PNG"]', 66))
    _engine(syn, "toolkits", "pdf_ext", "", routes=route.format('files = ["ext:.pdf"]', 66)
            + route.format('category = ["forensics"]\nfiles = ["ext:.pdf"]', 80))
    _engine(syn, "toolkits", "aaa_tie", "", routes=route.format('files = ["name:cap.*"]', 66))
    _engine(syn, "toolkits", "kw_and_file", "", routes=route.format('keywords = ["image"]\nfiles = ["ext:.png"]', 71))
    ms = manifest.discover(REPO) + manifest.discover(syn)
    folder = tmp_path / "files"
    pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    _heads(folder, {"pic.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, "doc.pdf": pdf, "cap.pcap": b"\xd4\xc3\xb2\xa1"})
    for cat, desc in [("forensics", "a pdf and an image"), ("crypto", "an RSA modulus with a small e"),
                      ("misc", ""), ("web", "jinja template injection")]:
        want = [(h.manifest.id, (h.priority, h.reason)) for h in router.route(cat, desc, folder, manifests=ms)]
        got = list(E.route_hits(ms, cat, desc, E.input_files(folder)).items())
        assert got == want, cat
    hits = E.route_hits(ms, "forensics", "a pdf and an image", E.input_files(folder))
    assert hits["toolkits.pdf_ext"] == (80, "category forensics, doc.pdf has .pdf")      # the best route
    syn_order = [e for e in hits if e in {"toolkits.png_magic", "toolkits.aaa_tie", "toolkits.kw_and_file"}]
    assert syn_order == ["toolkits.kw_and_file", "toolkits.aaa_tie", "toolkits.png_magic"]  # ties by id


def test_sweep_files_are_not_inputs_and_claims_name_engines_per_file(root, tmp_path):
    folder = tmp_path / "unpacked"
    heads = _heads(folder, {".sweep.json": b"{}", ".sweep-owner": b"", "sub/.sweep.json": b"{}", "a.txt": b"",
                            "z.bin": b""})
    assert [f.relative_to(folder).as_posix() for f, _ in heads] == ["a.txt", "z.bin", "sub/.sweep.json"]
    claims = E.claims(_ms(root), heads, folder)
    assert set(claims["a.txt"]) == {"toolkits.catflag", "toolkits.planner", "toolkits.pricey",
                                    "toolkits.needy", "toolkits.external"}
    assert "z.bin" not in claims


def test_input_files_skips_links(tmp_path):
    folder = tmp_path / "u"
    folder.mkdir()
    (folder / "real.txt").write_text("x")
    (folder / "link.txt").symlink_to(folder / "real.txt")
    (folder / "dl").symlink_to(folder, target_is_directory=True)
    assert [f.name for f, _ in E.input_files(folder)] == ["real.txt"]
    assert E.input_files(tmp_path / "missing") == [] and E.input_files(None) == []


def test_expand_args_fills_every_placeholder(tmp_path):
    from ctf.engines import manifest as M
    s = M.IntakeSpec(run="all-files", match=("ext:.x",), args=("-o", "{out}/r", "{files}", "--c={challenge}",
                                                                 "{folder}"))
    argv = E.expand_args(s, [tmp_path / "a", tmp_path / "b"], folder=tmp_path / "f", challenge=tmp_path / "c",
                         out=tmp_path / "o")
    assert argv == ["-o", f"{tmp_path}/o/r", str(tmp_path / "a"), str(tmp_path / "b"), f"--c={tmp_path}/c",
                    str(tmp_path / "f")]


def test_engine_env_drops_secret_names_and_sets_the_event(monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "t")
    monkeypatch.setenv("CTF_COOKIE", "c")
    monkeypatch.setenv("GITHUB_API_KEY", "k")
    monkeypatch.setenv("MY_PASSWORD", "p")
    monkeypatch.setenv("KEEP_ME", "1")
    env = E.engine_env(SPOOKY)
    assert not {"CTF_TOKEN", "CTF_COOKIE", "GITHUB_API_KEY", "MY_PASSWORD"} & set(env)
    assert env["KEEP_ME"] == "1" and env["CTF_EVENT"] == "spooky"


# ---------------------------------------------------------------- one intake, in process

def _intake(root, wd, adapter, cid, profile=CSCTF, **kw):
    return I.intake_one(cid, profile, adapter=adapter, workdir=wd, options=_opts(root, **kw))


def test_one_intake_downloads_sweeps_runs_engines_and_writes_every_report(root, tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "never-reaches-an-engine")
    wd = tmp_path / "wd"
    flag = "CSCTF{zipped_b64_member}"
    handout = _zip({"logs/a.txt": "x " + base64.b64encode(flag.encode()).decode() + " y",
                    "logs/b|weird.txt": "nothing", "m.marker": ""})
    ad = FakeAdapter({"9076": (_ch("9076", "Last Buffer", "web", "Find it. Format CSCTF{...}"),
                               {"handout.zip": handout})})
    rep = _intake(root, wd, ad, "9076")
    d = wd / "9076-last-buffer"
    assert rep.dir == d.resolve() and (d / "files" / "handout.zip").read_bytes() == handout
    assert json.loads((d / "challenge.json").read_text())["description"] == "Find it. Format CSCTF{...}"
    # sweep: the member was unpacked and the base64 flag found; the function engine saw the marker
    assert (d / "unpacked" / "handout.zip.unpacked" / "logs" / "a.txt").is_file()
    assert set(rep.flags) == {flag, "CSCTF{from_function_1}"}
    assert rep.status == "candidate" and set(rep.result.flags) == {flag, "CSCTF{from_function_1}"}
    assert ad.submits == []
    runs = {(r.engine, r.inputs): r for r in rep.runs}
    cat = runs[("toolkits.catflag", ("unpacked/handout.zip.unpacked/logs/a.txt",))]
    out = (d / cat.output).read_text()
    assert cat.status == "ok" and cat.exit_code == 0
    assert "SECRET_ENV []" in out and "EVENT csctf" in out and "CWD toolkits.catflag" in out
    fn = runs[("web.fn_engine", ())]
    assert fn.result_status == "solved" and fn.flags == ("CSCTF{from_function_1}",)
    # reports
    index = (d / I.INDEX).read_text()
    assert "status: **candidate**" in index and f"`{flag}`" in index and "nothing was submitted" in index
    assert "handout.zip -> logs/b\\|weird.txt" in index                 # a handout name cannot break the table
    assert "| toolkits.catflag | unpacked/handout.zip.unpacked/logs/a.txt | ok |" in index
    triage = (d / I.TRIAGE).read_text()
    assert "| handout.zip -> logs/a.txt |" in triage and "toolkits.catflag" in triage
    assert "web.fn_engine (priority 70): category web; ran at intake" in triage
    flags_txt = (d / I.FLAGS).read_text().splitlines()
    assert {ln.split("\t")[0] for ln in flags_txt} == {flag, "CSCTF{from_function_1}"}
    j = json.loads((d / I.REPORT).read_text())
    assert j["status"] == "candidate" and j["files"] == 1 and j["members"] == 3 and j["engines"] == len(rep.runs)
    assert set(j["stages"]) == {"download", "sweep", "engines", "fastlane"} and j["net_guard"]["mode"] == "hook"
    assert "## intake" in (d / "notes.md").read_text()
    recs = [r for r in ledger.read(wd) if r["event"] == "intake"]
    assert len(recs) == 1 and recs[0]["challenge_id"] == "9076" and recs[0]["status"] == "candidate"
    assert recs[0]["flags"] == 2 and recs[0]["files"] == 1 and recs[0]["members"] == 3
    runs_rec = [r for r in ledger.read(wd) if r["event"] == "engine.run"]
    assert {r["via"] for r in runs_rec} == {"intake"} and {r["challenge_id"] for r in runs_rec} == {"9076"}
    assert len(runs_rec) == len(rep.runs)


def test_one_flag_is_solved_and_brief_or_placeholder_flags_are_excluded(root, tmp_path):
    wd = tmp_path / "wd"
    files = {"a.txt": b"CSCTF{real_one} and CSCTF{example_from_brief} and CSCTF{...}"}
    ad = FakeAdapter({"1": (_ch("1", description="e.g. CSCTF{example_from_brief}"), files)})
    rep = _intake(root, wd, ad, "1")
    assert rep.status == "solved" and rep.result.flags == ("CSCTF{real_one}",)
    assert set(rep.excluded) == {"CSCTF{example_from_brief}", "CSCTF{...}"}
    assert rep.result.evidence and "CSCTF{real_one}" in rep.result.evidence[0].detail
    cat = next(r for r in rep.runs if r.engine == "toolkits.catflag")      # a legacy-output engine:
    assert "CSCTF{real_one}" in cat.flags                                  # its stdout is scanned
    assert any(w.startswith("engine toolkits.catflag on unpacked/a.txt") for w in rep.flags["CSCTF{real_one}"])


def test_engine_only_flags_count_and_engine_output_flags_are_filtered_like_the_sweeps(root, tmp_path):
    wd = tmp_path / "wd"
    ad = FakeAdapter({"2": (_ch("2", description="flag looks like CSCTF{brief_text}"),
                            {"r.res": b"CSCTF{from_json_engine}", "q.res": b"CSCTF{brief_text}"})})
    rep = _intake(root, wd, ad, "2")
    # the sweep sees the same bytes, so check the engine's own contribution in the where-list
    assert any(w.startswith("engine toolkits.jsonres") for w in rep.flags["CSCTF{from_json_engine}"])
    assert "CSCTF{brief_text}" not in rep.flags and "CSCTF{brief_text}" in rep.excluded
    run = next(r for r in rep.runs if r.engine == "toolkits.jsonres" and r.inputs == ("unpacked/r.res",))
    assert run.result_status == "candidate" and run.flags == ("CSCTF{from_json_engine}",)


def test_an_engines_own_result_flags_win_over_format_matches_in_its_stdout(root, tmp_path):
    """The engine prints a decoy in the event format and then its SolverResult naming another flag:
    only the result's flag is the engine's, and only it reaches the intake result."""
    ad = FakeAdapter({"12": (_ch("12"), {"c.pick": b"no flag in the handout"})})
    rep = _intake(root, tmp_path / "wd", ad, "12")
    run = next(r for r in rep.runs if r.engine == "toolkits.chooser")
    assert "CSCTF{stdout_decoy}" in (rep.dir / run.output).read_text()      # the decoy was printed
    assert run.result_status == "candidate" and run.flags == ("CSCTF{the_chosen_one}",)
    assert set(rep.flags) == {"CSCTF{the_chosen_one}"}
    # The engine said `candidate`, so intake keeps it a candidate (B-090), never `solved`.
    assert rep.status == "candidate" and rep.result.flags == ("CSCTF{the_chosen_one}",)


def test_a_metadata_join_equal_to_a_found_flag_is_listed_once(root, tmp_path):
    """Two distinct flags found, and the sweep's metadata join rebuilds one of them: the candidate
    lists each flag once and carries no join evidence for the duplicate."""
    import test_fragjoin as frag
    joined = "spooky{split_across_three_containers}"
    ad = FakeAdapter({"13": (_ch("13"), {"tanny.png": frag.tanny_png(),
                                         "a.txt": f"{joined} and spooky{{another_one}}".encode()})})
    rep = I.intake_one("13", SPOOKY, adapter=ad, workdir=tmp_path / "wd", options=_opts(root, engines=False))
    sweep_joins = [j.flag for j, _ in rep.sweep.joins]
    assert sweep_joins[0] == joined                                           # the sweep did join it
    assert set(rep.flags) == {joined, "spooky{another_one}"}
    assert rep.status == "candidate"
    assert rep.result.flags.count(joined) == 1
    assert len(rep.result.flags) == len(set(rep.result.flags))
    others = [j for j in sweep_joins if j != joined]                          # the other fragment joins stay
    assert list(rep.result.flags) == [joined, "spooky{another_one}", *others] or \
        list(rep.result.flags) == ["spooky{another_one}", joined, *others]
    assert not [e for e in rep.result.evidence if e.kind == "join" and e.detail.startswith(joined)]
    assert f"2 distinct flag(s) and {len(others)} metadata join(s)" in rep.result.notes


def test_engine_flag_the_sweep_cannot_see_makes_the_result(root, tmp_path):
    """A flag only an engine prints (here the function engine) is solved by intake alone."""
    wd = tmp_path / "wd"
    ad = FakeAdapter({"3": (_ch("3", category="web"), {"m.marker": b"no flag here"})})
    rep = _intake(root, wd, ad, "3")
    assert rep.status == "solved" and rep.result.flags == ("CSCTF{from_function_1}",)
    assert rep.flags["CSCTF{from_function_1}"][0].startswith("engine web.fn_engine")


def test_engines_are_denied_the_network(root, tmp_path):
    lst = socket.socket()
    lst.bind(("127.0.0.1", 0))
    lst.listen(2)
    lst.setblocking(False)
    try:
        ad = FakeAdapter({"4": (_ch("4"), {"x.probe": str(lst.getsockname()[1]).encode(), "y.sneak": b""})})
        rep = _intake(root, tmp_path / "wd", ad, "4")
        out = {r.engine: (rep.dir / r.output).read_text() + (rep.dir / r.errors).read_text() for r in rep.runs}
        assert "REFUSED intake network guard" in out["toolkits.netprobe"]
        assert "CONNECTED" not in out["toolkits.netprobe"]
        assert "subprocess.Popen" in out["toolkits.sneaky"] and "SPAWNED" not in out["toolkits.sneaky"]
        with pytest.raises(BlockingIOError):
            lst.accept()
    finally:
        lst.close()


def test_a_slow_engine_is_killed_at_its_timeout_and_recorded(root, tmp_path):
    wd = tmp_path / "wd"
    ad = FakeAdapter({"5": (_ch("5"), {"z.slow": b"30"})})
    rep = _intake(root, wd, ad, "5")
    run = next(r for r in rep.runs if r.engine == "toolkits.sleeper")
    assert run.status == "timeout" and run.exit_code is None and run.seconds < 10
    assert "killed after 2s" in run.note
    rec = [r for r in ledger.read(wd) if r["event"] == "engine.run" and r["engine"] == "toolkits.sleeper"]
    assert len(rec) == 1 and rec[0]["exit_code"] == -9 and rec[0]["via"] == "intake"


def test_the_engine_budget_cuts_the_running_engine_and_skips_the_rest(root, tmp_path):
    ad = FakeAdapter({"6": (_ch("6"), {"a.slow": b"30", "b.slow": b"30"})})
    rep = _intake(root, tmp_path / "wd", ad, "6", engine_budget=1.0)
    (first,) = rep.runs                       # the second never starts
    assert first.engine == "toolkits.sleeper" and first.inputs == ("unpacked/a.slow",)
    assert first.status == "timeout" and first.seconds < 1.8   # cut at the budget, not at its own 2 s
    skipped = [s.reason for s in rep.plan.skipped if s.engine == "toolkits.sleeper"]
    assert skipped == ["the intake engine budget of 1s was spent"]
    assert [j.files for j in rep.plan.jobs] == [(rep.dir / "unpacked" / "a.slow",)]    # jobs = what ran


def test_no_engine_starts_with_less_than_the_minimum_slice_of_budget_left(root, tmp_path):
    """A 0.3 s budget is under MIN_ENGINE_SLICE (0.5 s): nothing is started, every job is a skip."""
    assert I.MIN_ENGINE_SLICE == 0.5
    ad = FakeAdapter({"15": (_ch("15"), {"a.txt": b"x"})})
    rep = _intake(root, tmp_path / "wd", ad, "15", engine_budget=0.3)
    assert rep.runs == [] and rep.plan.jobs == []
    assert [s.reason for s in rep.plan.skipped if s.engine == "toolkits.catflag"] == [
        "the intake engine budget of 0.3s was spent"]
    assert not (rep.dir / "recon" / "engines").exists()


def test_engine_output_is_capped_and_a_missing_result_line_is_named(root, tmp_path, monkeypatch):
    monkeypatch.setattr(E, "OUT_CAP", 64)
    ad = FakeAdapter({"11": (_ch("11"), {"big.txt": b"A" * 5000, "n.nojson": b"CSCTF{printed_plainly}",
                                         "e.errout": b"E" * 5000})})
    rep = _intake(root, tmp_path / "wd", ad, "11")
    cat = next(r for r in rep.runs if r.engine == "toolkits.catflag")
    assert (rep.dir / cat.output).stat().st_size == 64 and "stdout cut to 64 of" in cat.note
    err = next(r for r in rep.runs if r.engine == "toolkits.errcat")
    assert (rep.dir / err.errors).stat().st_size == 64 and "stderr cut to 64 of 5000 bytes" in err.note
    assert (rep.dir / err.errors).read_bytes() == b"E" * 64 and "stdout cut" not in err.note
    nj = next(r for r in rep.runs if r.engine == "toolkits.nojson")
    assert nj.result_status is None and "no SolverResult JSON line" in nj.note
    assert nj.flags == ("CSCTF{printed_plainly}",)


def test_no_engines_still_plans_for_triage(root, tmp_path):
    ad = FakeAdapter({"7": (_ch("7"), {"a.txt": b"x"})})
    rep = _intake(root, tmp_path / "wd", ad, "7", engines=False)
    assert rep.runs == [] and not (rep.dir / "recon" / "engines").exists()
    assert {s.reason for s in rep.plan.skipped if s.engine == "toolkits.catflag"} == {"engines not run (--no-engines)"}
    assert "engines not run (--no-engines)" in rep.notes


def test_an_unavailable_os_guard_runs_no_engine_and_says_so(root, tmp_path, monkeypatch):
    monkeypatch.setitem(G._PROBE, "os", (None, "probe said no"))
    ad = FakeAdapter({"8": (_ch("8"), {"a.txt": b"x"})})
    rep = _intake(root, tmp_path / "wd", ad, "8", net_guard="os")
    assert rep.runs == []
    assert any("engines NOT RUN" in n and "probe said no" in n for n in rep.notes)
    assert "probe said no" in (rep.dir / I.INDEX).read_text()


def test_platform_failures_are_blocked_and_named(root, tmp_path):
    wd = tmp_path / "wd"
    ad = FakeAdapter({"9": (_ch("9", "Nine"), {"a.txt": b"x"})}, fail_download={"9"})
    rep = _intake(root, wd, ad, "9")
    assert rep.status == "blocked" and "HTTP 500" in rep.error and "HTTP 500" in rep.result.notes
    assert "error: PlatformError: download_files(9): HTTP 500" in (wd / "9-nine" / I.INDEX).read_text()
    rep = _intake(root, wd, ad, "404")
    assert rep.status == "blocked" and rep.dir is None and "HTTP 404" in rep.error
    assert [r["status"] for r in ledger.read(wd) if r["event"] == "intake"] == ["blocked", "blocked"]


def test_a_challenge_without_files_is_none_not_a_failure(root, tmp_path):
    rep = _intake(root, tmp_path / "wd", FakeAdapter({"10": (_ch("10", category="web"), {})}), "10")
    assert rep.status == "none" and "sweep: no handout files" in rep.notes
    assert [r.engine for r in rep.runs] == ["web.fn_engine"]


def test_options_are_checked():
    for kw, msg in [({"max_cost": "x"}, "max_cost"), ({"engine_budget": 0}, "engine_budget"),
                    ({"net_guard": "off"}, "net_guard")]:
        with pytest.raises(I.IntakeError, match=msg):
            I.Options(**kw)
    assert I.Options(engines=False, record=False, root=Path("/r")).argv() == [
        "--max-cost", "cheap", "--engine-budget", "60.0", "--net-guard", "auto", "--no-engines", "--no-ledger",
        "--root", "/r"]


def test_challenge_dir_matches_pull_and_refuses_unusable_ids(tmp_path):
    from ctf import config, workspace
    assert I.challenge_dir(tmp_path, _ch("9076", "Last Buffer!")) == tmp_path / "9076-last-buffer"
    cfg = config.Config(base_url="http://127.0.0.1:9", token=None, team_id=None, workdir=tmp_path / "pull")
    for cid, name in [("9076", "Last Buffer!"), ("0042", "Zero Padded"), ("7", "")]:
        pulled = workspace.for_challenge({"id": cid, "name": name}, cfg).dir      # what `ctf pull` makes
        assert I.challenge_dir(tmp_path / "pull", _ch(cid, name)) == pulled, cid
    assert I.challenge_dir(tmp_path, _ch("0042", "Zero Padded")) == tmp_path / "42-zero-padded"
    assert I.challenge_dir(tmp_path, _ch("a/../b", "X")) == tmp_path / "a-..-b-x"
    assert I.challenge_dir(tmp_path, _ch("gm-17", "X")) == tmp_path / "gm-17-x"
    with pytest.raises(I.IntakeError):
        I.challenge_dir(tmp_path, _ch("///", "X"))


# ---------------------------------------------------------------- the board and many at once

def test_board_skips_solved_and_already_taken(tmp_path):
    wd = tmp_path / "wd"
    ad = FakeAdapter({"1": (_ch("1", "A"), {}), "2": (_ch("2", "B", solved=True), {}), "3": (_ch("3", "C"), {})})
    (wd / "3-c" / "recon").mkdir(parents=True)
    (wd / "3-c" / I.REPORT).write_text('{"status": "none"}')
    take, skipped = I.board(CSCTF, adapter=ad, workdir=wd)
    assert take == ["1"] and dict(skipped)["2"] == "solved by the team"
    assert "already taken in" in dict(skipped)["3"] and ": none)" in dict(skipped)["3"]
    assert I.board(CSCTF, adapter=ad, workdir=wd, include_solved=True, force=True)[0] == ["1", "2", "3"]


def test_a_blocked_intake_is_taken_again_by_the_next_board(root, tmp_path):
    """A download that failed at wave open (HTTP 500) leaves a blocked recon/intake.json; the next
    board takes the challenge again without --force, and once it is through it is skipped."""
    wd = tmp_path / "wd"
    ad = FakeAdapter({"9": (_ch("9", "Nine"), {"a.txt": b"x"})}, fail_download={"9"})
    rep = _intake(root, wd, ad, "9", engines=False)
    assert rep.status == "blocked" and json.loads((wd / "9-nine" / I.REPORT).read_text())["status"] == "blocked"
    assert I.finished(wd / "9-nine") is None
    assert I.board(CSCTF, adapter=ad, workdir=wd) == (["9"], [])
    ad.fail_download.clear()
    assert _intake(root, wd, ad, "9", engines=False).status == "none"
    assert I.finished(wd / "9-nine") == "none"
    take, skipped = I.board(CSCTF, adapter=ad, workdir=wd)
    assert take == [] and "already taken in" in dict(skipped)["9"]


@pytest.mark.parametrize("text", ["not json", "[1, 2]", '{"status": 3}', "{}"])
def test_an_unreadable_intake_report_is_taken_again(tmp_path, text):
    wd = tmp_path / "wd"
    ad = FakeAdapter({"1": (_ch("1", "A"), {})})
    (wd / "1-a" / "recon").mkdir(parents=True)
    (wd / "1-a" / I.REPORT).write_text(text)
    assert I.finished(wd / "1-a") is None
    assert I.board(CSCTF, adapter=ad, workdir=wd) == (["1"], [])


def test_many_in_threads_runs_each_once(root, tmp_path):
    ad = FakeAdapter({str(i): (_ch(str(i), f"c{i}"), {"a.txt": f"CSCTF{{f{i}}}".encode()}) for i in range(4)})
    seen = []
    outs = I.intake_many([str(i) for i in range(4)], CSCTF, spawn=False, adapter=ad, workdir=tmp_path / "wd",
                         options=_opts(root, engines=False), on_done=lambda o: seen.append(o.challenge_id))
    assert [o.challenge_id for o in outs] == ["0", "1", "2", "3"] and sorted(seen) == ["0", "1", "2", "3"]
    assert [o.report.result.flags for o in outs] == [(f"CSCTF{{f{i}}}",) for i in range(4)]
    assert all(o.ok for o in outs)


def test_many_refuses_bad_calls(tmp_path):
    with pytest.raises(I.IntakeError, match="twice"):
        I.intake_many(["1", "1"], CSCTF, workdir=tmp_path)
    with pytest.raises(I.IntakeError, match="jobs must be >= 1"):
        I.intake_many(["1"], CSCTF, workdir=tmp_path, jobs=0)
    with pytest.raises(I.IntakeError, match="spawn=False"):
        I.intake_many(["1"], CSCTF, workdir=tmp_path, adapter=FakeAdapter({}))
    assert I.intake_many([], CSCTF, workdir=tmp_path) == []
    assert I.default_jobs(3) == 3 and 1 <= I.default_jobs(10_000) <= I.MAX_JOBS


def _drop(wd: Path, cid: str, files: dict, meta: str = ""):
    d = wd / "drop" / cid
    d.mkdir(parents=True)
    for rel, data in files.items():
        (d / rel).write_bytes(data)
    if meta:
        (d / "challenge.toml").write_text(meta)


def _intervals(wd: Path, outs):
    iv = []
    for o in outs:
        j = json.loads((Path(o.summary["dir"]) / I.REPORT).read_text())
        iv.append((j["started"], j["started"] + j["seconds"]))
    return iv


def test_workers_are_processes_that_run_in_parallel(root, tmp_path):
    """Manual mode (no network at all): three drop folders, one worker process each, all at once."""
    wd = tmp_path / "wd"
    for i in range(3):
        _drop(wd, f"c{i}", {"s.slow": b"1.5", "f.txt": f"spooky{{w{i}}}".encode()})
    outs = I.intake_many(["c0", "c1", "c2"], SPOOKY, workdir=wd, options=_opts(root), jobs=3)
    assert [o.ok for o in outs] == [True] * 3, [o.log.read_text() for o in outs]
    assert [o.summary["flags"] for o in outs] == [[f"spooky{{w{i}}}"] for i in range(3)]
    assert max(o.started for o in outs) < 3.0                # every worker started within 3 s
    for o in outs:                                           # the workers ran the given checkout's engines
        j = json.loads((Path(o.summary["dir"]) / I.REPORT).read_text())
        assert [r["engine"] for r in j["engines_run"]] == ["toolkits.catflag", "toolkits.sleeper"]
    iv = _intervals(wd, outs)
    assert max(s for s, _ in iv) < min(e for _, e in iv), f"workers did not overlap: {iv}"
    assert sorted(r["challenge_id"] for r in ledger.read(wd) if r["event"] == "intake") == ["c0", "c1", "c2"]


def test_jobs_limits_how_many_run_at_once(root, tmp_path):
    wd = tmp_path / "wd"
    for i in range(2):
        _drop(wd, f"s{i}", {"s.slow": b"1"})
    outs = I.intake_many(["s0", "s1"], SPOOKY, workdir=wd, options=_opts(root), jobs=1)
    (a0, a1), (b0, b1) = sorted(_intervals(wd, outs))
    assert b0 >= a1, "jobs=1 ran two workers at once"


def test_a_failed_worker_is_reported_not_hidden(root, tmp_path):
    wd = tmp_path / "wd"
    _drop(wd, "ok", {"a.txt": b"x"})
    (wd / "drop" / "ok2").mkdir()
    outs = I.intake_many(["ok", "missing"], SPOOKY, workdir=wd, options=_opts(root, engines=False))
    assert outs[0].ok and outs[0].summary["status"] == "none"
    assert not outs[1].ok and outs[1].exit_code == 1 and outs[1].summary["status"] == "blocked"
    assert "no drop folder for challenge 'missing'" in outs[1].log.read_text()


def test_worker_main_reports_a_crash_as_json(tmp_path, capsys):
    code = I.worker_main(["--event", "no-such-event-b002", "--id", "1"])
    out = capsys.readouterr().out.strip().splitlines()
    assert code == 1 and json.loads(out[-1])["status"] == "error" and "no-such-event-b002" in out[-1]


# ---------------------------------------------------------------- the CLI

def test_cli_intake_all_in_manual_mode(root, tmp_path, monkeypatch, capsys):
    from ctf import cli
    wd = tmp_path / "wd"
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    _drop(wd, "one", {"a.txt": b"spooky{cli_found}"}, 'name = "One"\ncategory = "misc"\n')
    _drop(wd, "two", {"b.txt": b"nothing"})
    (wd / "drop" / "two" / "SOLVED").write_text("teammate\n")
    assert cli.main(["intake", "--all", "--event", "spooky", "--no-engines"]) == 0
    out = capsys.readouterr().out
    assert "skip two: solved by the team" in out and "intake one: solved" in out and "spooky{cli_found}" in out
    assert "1/1 ran; all started within" in out
    assert (wd / "one-one" / I.INDEX).is_file()
    # a second --all finds nothing new
    assert cli.main(["intake", "--all", "--event", "spooky"]) == 0
    assert "nothing to take in" in capsys.readouterr().out


def test_cli_usage_and_guard_errors_exit_2(tmp_path, monkeypatch, capsys):
    from ctf import cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert cli.main(["intake", "--event", "spooky"]) == 2
    assert cli.main(["intake", "1", "--all", "--event", "spooky"]) == 2
    monkeypatch.setitem(G._PROBE, "os", (None, "no sandbox here"))
    assert cli.main(["intake", "1", "--event", "spooky", "--net-guard", "os"]) == 2
    assert "no sandbox here" in capsys.readouterr().err


def test_cli_exit_1_when_a_worker_fails(tmp_path, monkeypatch, capsys):
    from ctf import cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    (tmp_path / "drop").mkdir()
    assert cli.main(["intake", "ghost", "--event", "spooky", "--no-engines"]) == 1
    assert "FAIL" in capsys.readouterr().out


# ---------------------------------------------------------------- the repo's own adapters

def _png(w, h):
    import struct
    import zlib

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00" * (h * (1 + 3 * w)))) + chunk(b"IEND", b""))


def test_repo_adapters_run_on_a_handouts_image_and_pdf(tmp_path):
    """The two adapters shipped in the repo (file_properties, pdf_revisions) run at intake, inside the
    zip too, and their output carries the facts they exist for."""
    pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
           b"2 0 obj<<>>endobj\ntrailer<</Root 1 0 R/Prev 9>>\n%%EOF\n")
    ad = FakeAdapter({"20": (_ch("20", category="misc"),
                             {"pack.zip": _zip({"in/pic.png": _png(5, 4)}), "report.pdf": pdf})})
    rep = I.intake_one("20", CSCTF, adapter=ad, workdir=tmp_path / "wd", options=I.Options(net_guard="hook"))
    runs = {(r.engine, r.inputs): r for r in rep.runs}
    fp = runs[("metadata_forensics.file_properties", ("unpacked/pack.zip.unpacked/in/pic.png",))]
    assert fp.status == "ok" and "png.ihdr_dimensions_pixels = 5x4" in (rep.dir / fp.output).read_text()
    pr = runs[("toolkits.pdf_revisions", ("unpacked/report.pdf",))]
    out = (rep.dir / pr.output).read_text()
    assert pr.status == "ok" and "unpacked/report.pdf  pdf=True  revisions=" in out
    assert ("metadata_forensics.file_properties", ("unpacked/report.pdf",)) not in runs
