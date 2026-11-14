"""B-042: multi-delivery Mastery cases in the first-day regression set (ctf/openers/sets.py,
ctf/openers/set_fixtures.py, openers.run_input, the lane gate's key).

A case whose input is a saved attempt runs the opener's engine once per set on the set's own delivery.
The unit tests drive `sets.run` with a recording stand-in for the engine run (what it is handed is the
thing under test); the shipped cases run the real engines under the network guard."""
from __future__ import annotations

import io
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from ctf import deliveries, openers, paths
from ctf.adapt import regress
from ctf.engines import runner
from ctf.intake import guard as G
from ctf.openers import fixtures, set_fixtures, sets

import adapt_repo as AR

REPO = paths.repo_root()
SET_LANES = {                      # lane -> (its multi-delivery cases, its crossed control)
    "warmups": (("warmups_mastery_deliveries", "warmups_mastery_bundle"), "warmups_mastery_crossed"),
    "script-analysis": (("powershell_mastery_deliveries",), "powershell_mastery_crossed"),
    "metadata-forensics": (("metadata_mastery_bundle",), "metadata_mastery_crossed"),
    "mobile-android": (("apk_mastery_deliveries",), "apk_mastery_crossed"),
    "binary": (("elf64_mastery_deliveries",), "elf64_mastery_crossed"),
}
HOOK_SAFE = sorted(set(SET_LANES) - {"binary"})       # the binary engine loads capstone: OS sandbox only


class Recorder:
    """Stands in for one guarded engine run: records the file it is handed and answers its bytes."""

    def __init__(self, codes=(), err=""):
        self.seen, self.codes, self.err = [], list(codes), err

    def __call__(self, path: Path, cwd: Path):
        data = Path(path).read_bytes()
        self.seen.append((Path(path).name, data, cwd.name))
        code = self.codes.pop(0) if self.codes else 0
        out = f"{path}: {data.decode()}\nsecond line\n"
        return openers.EngineRun(code, out, self.err and f"warning about {path}\n", 0.25)


def q(n, artifact=""):
    return {"id": f"set{n}.answer", "question": "?", "artifact": artifact, "set": n}


def zipped(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members:
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0)), body)
    return buf.getvalue()


# --------------------------------------------------------------------------- sets.run

def test_each_set_runs_on_its_own_delivery_and_its_lines_say_so(tmp_path):
    att = set_fixtures.write_attempt(tmp_path / "in", [("blob.txt", b"ONE"), ("blob.txt", b"TWO")],
                                     [q(1, "delivery 2: blob.txt"), q(2, "delivery 1: blob.txt")])
    rec = Recorder(err="yes")
    code, out, err, seconds = sets.run(att, tmp_path / "run", rec)
    assert code == 0 and seconds == 0.5
    assert rec.seen == [("blob.txt", b"TWO", "set-01"), ("blob.txt", b"ONE", "set-02")]
    assert out.splitlines() == ["set1 <- delivery 2: blob.txt [named]", "set1> delivery 2: blob.txt: TWO",
                                "set1> second line", "set2 <- delivery 1: blob.txt [named]",
                                "set2> delivery 1: blob.txt: ONE", "set2> second line"]
    assert err.splitlines() == ["set1> warning about delivery 2: blob.txt", "set2> warning about delivery 1: blob.txt"]
    assert str(tmp_path) not in out + err, "the engine's file path is replaced by the delivery"


def test_a_bundle_members_bytes_are_what_the_engine_is_handed(tmp_path):
    bundle = zipped([("blob-02.txt", b"TWO"), ("blob-01.txt", b"ONE")])
    att = set_fixtures.write_attempt(tmp_path / "in", [("mastery.zip", bundle)], [q(1), q(2)])
    rec = Recorder()
    code, out, _, _ = sets.run(att, tmp_path / "run", rec)
    assert code == 0 and [(n, d) for n, d, _ in rec.seen] == [("blob-01.txt", b"ONE"), ("blob-02.txt", b"TWO")]
    assert "set2> delivery 1: mastery.zip -> blob-02.txt: TWO" in out.splitlines()


def test_an_unmapped_set_is_not_run_and_fails_the_run(tmp_path):
    att = set_fixtures.write_attempt(tmp_path / "in", [("blob.txt", b"ONE"), ("blob.txt", b"TWO")],
                                     [q(1, "delivery 1: blob.txt"), q(2, "delivery 2: blob.txt"),
                                      q(3, "delivery 3: blob.txt")])
    rec = Recorder()
    code, out, _, _ = sets.run(att, tmp_path / "run", rec)
    assert code == sets.UNMAPPED_EXIT and len(rec.seen) == 2
    assert out.splitlines()[-1] == ("set3 <- UNMAPPED: its questions name delivery 3, and the attempt has 2")
    assert "set3>" not in out


def test_exit_code_is_the_first_engine_failure_then_unmapped_and_a_cut_stops_the_run(tmp_path):
    def attempt(name):
        return set_fixtures.write_attempt(tmp_path / name, [("blob.txt", b"ONE"), ("blob.txt", b"TWO")],
                                          [q(1, "delivery 1: blob.txt"), q(2, "delivery 2: blob.txt"),
                                           q(3, "delivery 9: blob.txt")])
    assert sets.run(attempt("a"), tmp_path / "ra", Recorder(codes=[0, 7]))[0] == 7, "an engine failure outranks unmapped"
    assert sets.run(attempt("b"), tmp_path / "rb", Recorder(codes=[5, 7]))[0] == 5
    rec = Recorder(codes=[None, 0])
    code, out, _, seconds = sets.run(attempt("c"), tmp_path / "rc", rec)
    assert code is None and len(rec.seen) == 1 and seconds == 0.25, "a cut set ends the run: later sets are not run"
    assert "set2" not in out


def test_an_attempt_that_cannot_be_read_runs_nothing(tmp_path):
    att = set_fixtures.write_attempt(tmp_path / "in", [("blob.txt", b"ONE"), ("blob.txt", b"TWO")], [q(1), q(2)])
    (att.parent / "artifact" / "delivery-02" / "blob.txt").write_bytes(b"changed after the attempt was saved")
    rec = Recorder()
    code, out, err, seconds = sets.run(att, tmp_path / "run", rec)
    assert (code, out, seconds, rec.seen) == (sets.UNREADABLE_EXIT, "", 0.0, [])
    assert err.startswith("sets: delivery 2 of 2:") and "has sha256" in err
    assert not (tmp_path / "run").exists()
    # one set over two deliveries: an opener engine reads one file
    att = set_fixtures.write_attempt(tmp_path / "one", [("a.bin", b"a"), ("b.bin", b"b")],
                                     [{"id": "answer", "question": "?"}])
    code, _, err, _ = sets.run(att, tmp_path / "run2", rec)
    assert code == sets.UNREADABLE_EXIT and "no per-set input" in err and rec.seen == []


# --------------------------------------------------------------------------- run_input, with a real engine

@pytest.fixture
def probe_root(tmp_path, monkeypatch):
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    return AR.make_repo(tmp_path)


def test_run_input_runs_the_engine_once_per_set_and_leaves_other_inputs_alone(probe_root, tmp_path):
    g = G.resolve("hook")
    att = set_fixtures.write_attempt(tmp_path / "in", [("blob.txt", b"ONE"), ("blob.txt", b"TWO")],
                                     [q(1, "delivery 1: blob.txt"), q(2, "delivery 2: blob.txt")])
    r = openers.run_input(AR.ENGINE, att, root=probe_root, g=g, run_dir=tmp_path / "run", work=tmp_path / "work",
                          timeout=120)
    assert r.code == 0, r.err
    assert r.out.splitlines() == ["set1 <- delivery 1: blob.txt [named]", "set1> " + AR.answer_for(b"ONE"),
                                  "set2 <- delivery 2: blob.txt [named]", "set2> " + AR.answer_for(b"TWO")]
    assert r.seconds > 0 and not r.cut
    # any other input is one plain engine run, on the file itself
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"ONE")
    r = openers.run_input(AR.ENGINE, plain, root=probe_root, g=g, run_dir=tmp_path / "run2", work=tmp_path / "work",
                          timeout=120)
    assert r.code == 0 and r.out.splitlines() == [AR.answer_for(b"ONE")]
    # attempt.json is run per set, never read as the engine's input
    assert AR.answer_for(att.read_bytes()) not in r.out


def test_run_input_reports_a_cut_set_as_a_cut_run(probe_root, tmp_path, monkeypatch):
    # A hung engine: the run is killed at the cap, which is real elapsed time by nature (lower bound only).
    monkeypatch.setenv("ADAPT_PROBE_SLEEP", "60")
    att = set_fixtures.write_attempt(tmp_path / "in", [("blob.txt", b"ONE"), ("blob.txt", b"TWO")], [q(1), q(2)])
    r = openers.run_input(AR.ENGINE, att, root=probe_root, g=G.resolve("hook"), run_dir=tmp_path / "run",
                          work=tmp_path / "work", timeout=1.0)
    assert r.cut and r.code is None and r.seconds >= 1.0
    assert r.out.splitlines() == ["set1 <- delivery 1: blob.txt [position]"], "set 2 is not started after the cut"


# --------------------------------------------------------------------------- the shipped cases

def test_every_set_fixture_is_a_readable_attempt_with_several_sets(tmp_path):
    for kind in set_fixtures.BUILDERS:
        assert fixtures.BUILDERS[kind] is set_fixtures.BUILDERS[kind], kind
        p = fixtures.build(kind, tmp_path / kind)
        assert deliveries.is_attempt(p), kind
        inputs = deliveries.set_inputs(deliveries.read_attempt(p))
        assert len(inputs) >= 2 and all(i.choice.mapped and i.data for i in inputs), kind
        assert len({i.data for i in inputs}) == len(inputs), f"{kind}: every set has bytes of its own"


def test_the_fixtures_share_file_and_member_names_across_sets(tmp_path):
    """The shapes that made a neighbour's delivery answerable: same delivery name, same member name."""
    s = deliveries.read_attempt(fixtures.build("warmups_mastery_deliveries", tmp_path / "w"))
    assert s.names == ("blob.txt",) * 3 and all(b.startswith(b"01\t") for b in s.blobs)
    s = deliveries.read_attempt(fixtures.build("powershell_mastery_deliveries", tmp_path / "p"))
    assert s.names == ("evidence.zip",) * 2
    assert [zipfile.ZipFile(io.BytesIO(b)).namelist() for b in s.blobs] == [["resource-sample.ps1"]] * 2
    assert all(deliveries.named_delivery(x) is None for x in s.attempt["questions"]), "the position rule's shape"
    for kind, first in (("warmups_mastery_bundle", "blob-02.txt"), ("metadata_mastery_bundle", "metadata-evidence-02.zip")):
        s = deliveries.read_attempt(fixtures.build(kind, tmp_path / kind))
        assert len(s.blobs) == 1 and zipfile.ZipFile(io.BytesIO(s.blobs[0])).namelist()[0] == first, \
            f"{kind}: the bundle lists set 2's member first"


@pytest.mark.parametrize("lane", sorted(SET_LANES))
def test_shipped_declaration_has_the_multi_delivery_cases_and_their_control(lane):
    o = openers.for_lane(lane)
    cases, control = SET_LANES[lane]
    by = {c.fixture: c for c in o.all_cases}
    for kind in cases:
        assert kind in by and by[kind].mode == "mastery", kind
        assert all(e.startswith(("set1", "set2", "set3")) for e in by[kind].expect), "the key names the set"
        assert {e.split(">")[0].split(" ")[0] for e in by[kind].expect} >= {"set1", "set2"}, "and every set"
    assert control in o.controls


def _keys_hold_and_the_crossed_control_tells(lane, run):
    """`run(kind, n)` -> an EngineRun of the lane's engine over that fixture, per set."""
    o = openers.for_lane(lane)
    cases, control = SET_LANES[lane]
    by = {c.fixture: c for c in o.all_cases}
    for n, kind in enumerate(cases):
        r = run(kind, n)
        assert r.code == 0, r.err
        missing = [e for e in by[kind].expect if e not in r.out]
        assert not missing, f"{kind}: {missing}\n{r.out}"
    crossed = run(control, 99)
    assert crossed.code == 0, crossed.err
    first = by[cases[0]]
    answers = [e.split("> ", 1)[1].split(": ")[-1] if "> " in e else None for e in first.expect]
    answers = [a for a in answers if a]
    assert answers and all(a in crossed.out for a in answers), "the control still prints every answer"
    for kind in cases:
        assert not all(e in crossed.out for e in by[kind].expect), f"{kind}'s key holds on the crossed control"
    wrong = [e for e in first.expect if "> " in e and e not in crossed.out]
    assert len(wrong) >= 2, "sets 1 and 2 both print the other's answer"


@pytest.mark.parametrize("lane", HOOK_SAFE)
def test_the_real_engine_answers_each_set_from_its_own_delivery_and_the_crossed_control_tells(lane, tmp_path):
    """Each multi-delivery case's frozen key holds; on the control (two sets' files exchanged) every
    answer still comes out, under the wrong set, and no key holds."""
    o = openers.for_lane(lane)
    g = G.resolve("auto")

    def run(kind, n):
        return openers.run_input(o.engine, fixtures.build(kind, tmp_path / f"in-{n}"), root=REPO, g=g,
                                 run_dir=tmp_path / f"run-{n}", work=tmp_path / "work", timeout=240)

    _keys_hold_and_the_crossed_control_tells(lane, run)


@pytest.mark.needs_tool("py:capstone", "py:elftools")
def test_the_binary_engine_answers_each_set_from_its_own_elf(tmp_path):
    """The binary case, checked directly against binary.d01 through the same per-set runner: the gate
    can only arm it under the OS sandbox, which a sandboxed test run may lack (as tests/test_openers.py
    does for the binary base key)."""
    o = openers.for_lane("binary")

    def run(kind, n):
        def one(path, cwd):
            cwd.mkdir()
            cp = subprocess.run(runner.command(o.engine, [str(path)], via="arm", record=False), cwd=cwd,
                                capture_output=True, text=True, timeout=240,
                                env={**os.environ, "CTF_WORKDIR": str(tmp_path), "CTF_ENGINE_LEDGER": "0"})
            return openers.EngineRun(cp.returncode, cp.stdout, cp.stderr, 0.0)

        return openers.EngineRun(*sets.run(fixtures.build(kind, tmp_path / f"in-{n}"), tmp_path / f"run-{n}", one))

    _keys_hold_and_the_crossed_control_tells("binary", run)


@pytest.mark.needs_tool("py:capstone", "py:elftools")
def test_the_binary_opener_with_its_set_case_arms_under_the_os_sandbox():
    try:
        g = G.resolve("os")
    except G.GuardError as e:
        pytest.skip(f"OS network sandbox unavailable here, so the binary opener cannot be armed: {e}")
    r = openers.arm(openers.for_lane("binary"), guard=g, timeout=240)
    assert r.status == openers.ARMED, f"binary not armed: {r.reason}\n{r.output}"
    assert {c.fixture for c in r.cases} >= {"elf64_mastery_deliveries", "elf64_mastery_crossed"}


def test_a_pairing_that_reads_a_neighbours_delivery_fails_the_gate(monkeypatch):
    """The regression the cases exist for: break the pairing (every set reads delivery 1) and arming fails."""
    o = openers.for_lane("mobile-android")
    only = openers.Opener(lane=o.lane, category=o.category, engine=o.engine, label=o.label,
                          fixture="apk_mastery_deliveries",
                          expect=next(c.expect for c in o.all_cases if c.fixture == "apk_mastery_deliveries"),
                          controls=("apk_mastery_crossed",))
    assert openers.arm(only, timeout=240).status == openers.ARMED
    real = deliveries.choose

    def first_delivery(n, questions, sets_, count, members=None):
        c = real(n, questions, sets_, count, members)
        return deliveries.Choice(n, c.rule, index=0) if c.index is not None else c

    monkeypatch.setattr(deliveries, "choose", first_delivery)
    r = openers.arm(only, timeout=240)
    assert r.status == openers.FAILED
    assert r.missing == ("set2> delivery 2: sample_mastery_02.apk: ANS-B2B2B2B2B2B20002  [high] plain",)
    assert "set1> delivery 1: sample_mastery_01.apk: ANS-A1A1A1A1A1A10001  [high] plain" in r.found


# --------------------------------------------------------------------------- the lane gate

pytest_git = pytest.mark.needs_tool("git")


def _set_opener(tmp_path) -> str:
    att = fixtures.build("warmups_mastery_deliveries", tmp_path / "fx")
    saved = deliveries.read_attempt(att)
    key = [f"set{n}> {AR.answer_for(b)}" for n, b in enumerate(saved.blobs, 1)]
    return (f'[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "{AR.ENGINE}"\nlabel = "probe"\n'
            f'fixture = "{AR.BASE_FIXTURE}"\nexpect = ["{AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)}"]\n'
            f'controls = ["{AR.CONTROL_FIXTURE}", "warmups_mastery_crossed"]\n\n'
            f'[[opener.case]]\nmode = "mastery"\nfixture = "warmups_mastery_deliveries"\n'
            f'expect = {json.dumps(key)}\n')


@pytest_git
def test_the_lane_gate_replays_a_multi_delivery_case_per_set(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path, opener=_set_opener(tmp_path))
    wd = tmp_path / "work"
    wd.mkdir()
    g = regress.gate("probe", root=root, workdir=wd, load=0.0, cpus=1, guard="hook")
    got = {c.case: c.status for c in g.cases}
    assert g.verdict == regress.YES, g.reason
    assert got == {f"opener:{AR.BASE_FIXTURE}": regress.PASS, "opener:warmups_mastery_deliveries": regress.PASS,
                   f"control:{AR.CONTROL_FIXTURE}": regress.PASS, "control:warmups_mastery_crossed": regress.PASS}


@pytest_git
def test_the_gate_key_of_a_multi_delivery_case_covers_the_pairing_code(tmp_path, monkeypatch):
    """A warm PASS must not outlive a change to the set-to-delivery code; a single-file case's key is
    not touched by it."""
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for rel in regress.SET_CODE:
        assert (REPO / rel).is_file(), f"SET_CODE names {rel}, which is not in the tree"
    assert {"ctf/deliveries.py", "ctf/openers/sets.py", "ctf/openers/set_fixtures.py"} <= set(regress.SET_CODE)
    root = AR.make_repo(tmp_path, opener=_set_opener(tmp_path))
    marker = AR.write(root, "pairing.txt", "v1\n")
    monkeypatch.setattr(regress, "SET_CODE", ("pairing.txt",))

    def keys():
        keyer = regress.Keyer(root)
        out = {}
        for c in regress.regression_set("probe", root=root, workdir=None):
            out[c.name] = keyer.case_key(c, regress._runner.resolve(c.engine, root=root))
        return out

    before = keys()
    marker.write_text("v2\n")
    after = keys()
    assert after["opener:warmups_mastery_deliveries"] != before["opener:warmups_mastery_deliveries"]
    assert after["control:warmups_mastery_crossed"] != before["control:warmups_mastery_crossed"]
    assert after[f"opener:{AR.BASE_FIXTURE}"] == before[f"opener:{AR.BASE_FIXTURE}"]
    assert after[f"control:{AR.CONTROL_FIXTURE}"] == before[f"control:{AR.CONTROL_FIXTURE}"]
