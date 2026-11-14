"""B-174: `python -m ctf lookahead` end to end, in subprocesses, on synthetic matrices in tmp_path."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from ctf import ledger, paths

import lookahead_build as LB

REPO = paths.repo_root()


def ctf(tmp_path, *args):
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env["CTF_WORKDIR"] = str(tmp_path / "wd")
    return subprocess.run([sys.executable, "-m", "ctf", "lookahead", *args], cwd=str(REPO), env=env,
                          capture_output=True, text=True, timeout=300)


def _matrix(tmp_path, answered: bool):
    reader = LB.write_reader(tmp_path)
    m = tmp_path / "matrix"
    m.mkdir()
    (m / "prev.json").write_text(json.dumps([LB.q("a_total_size", "integer")]))
    (m / "base.json").write_text(json.dumps([LB.q("a_total_size", "integer"), LB.q("b")]))
    LB.matrix(tmp_path, {"probe": {"reader": reader, "base": "base.json", "previous": "prev.json"}})
    LB.specimen(m, "probe", "s", [LB.q("a_total_size", "integer"), LB.q("b")], {"x": b"12345"},
                key={"a_total_size": 5}, ctx={"answers": {"b": "bee"}} if answered else None)
    return m


def test_gate_green_exits_0_and_records(tmp_path):
    m = _matrix(tmp_path, answered=True)
    r = ctf(tmp_path, "gate", str(m), "--guard", "hook")
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("LOOKAHEAD probe: GREEN  0 gap(s);")
    (rec,) = [x for x in ledger.read(tmp_path / "wd") if x["event"] == "lookahead.gate"]
    assert rec["verdict"] == "green" and rec["questions"] == 2


def test_gate_red_exits_1_names_the_gap_and_writes_a_report_score_and_plan_read(tmp_path):
    m = _matrix(tmp_path, answered=False)
    rep = tmp_path / "report.json"
    r = ctf(tmp_path, "gate", str(m), "--guard", "hook", "--report-out", str(rep), "--no-record")
    assert r.returncode == 1, r.stderr
    assert "GAP unanswered" in r.stdout and "probe s/b: deterministic and unanswered" in r.stdout
    assert not ledger.path(tmp_path / "wd").exists()
    body = json.loads(rep.read_text())
    assert body[0]["counts"]["unanswered"] == 1

    fc = tmp_path / "forecast.toml"
    fc.write_text('day = "d2"\n[lane.probe]\nnew = ["c*"]\ngaps = []\n')
    r = ctf(tmp_path, "score", str(fc), "--lane", "probe", "--previous", str(m / "prev.json"),
            "--actual", str(m / "base.json"), "--report", str(rep))
    assert r.returncode == 0, r.stderr
    assert "0/1 new id(s) named" in r.stdout and "MISSED  b" in r.stdout and "GAP-MISSED b" in r.stdout
    (rec,) = [x for x in ledger.read(tmp_path / "wd") if x["event"] == "lookahead.score"]
    assert (rec["new"], rec["missed"], rec["gap_missed"]) == (1, 1, 1)

    r = ctf(tmp_path, "plan", str(m), "--report", str(rep))
    assert r.returncode == 1 and r.stdout.startswith("AGENT probe: 1 open gap(s) (unanswered); new shape: 1")


def test_gate_errors_exit_2_with_a_named_reason(tmp_path):
    r = ctf(tmp_path, "gate", str(tmp_path / "nothing"), "--guard", "hook")
    assert r.returncode == 2 and "no matrix folder" in r.stderr and "Traceback" not in r.stderr
    m = _matrix(tmp_path, answered=True)
    r = ctf(tmp_path, "gate", str(m), "--lane", "other", "--guard", "hook")
    assert r.returncode == 2 and "lane(s) other not in" in r.stderr


def test_thresholds_exit_1_on_an_undeclared_one(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "run.py").write_text("SIBLINGS_MAX = 256 * 1024\n")
    r = ctf(tmp_path, "thresholds", str(src))
    assert r.returncode == 0 and "SIBLINGS_MAX = 262144 (constant)" in r.stdout
    m = LB.matrix(tmp_path, {"warmups": {"reader": "r.py"}})
    r = ctf(tmp_path, "thresholds", str(src), "--matrix", str(m))
    assert r.returncode == 1 and r.stdout.startswith("UNDECLARED ")
    m2 = LB.matrix(tmp_path, {"warmups": {"reader": "r.py", "threshold": [{"name": "sib", "bytes": 262144}]}},
                   name="m2")
    r = ctf(tmp_path, "thresholds", str(src), "--matrix", str(m2), "--json")
    assert r.returncode == 0 and json.loads(r.stdout)["undeclared"] == []


def test_scale_writes_a_specimen(tmp_path):
    m = LB.matrix(tmp_path, {"probe": {"reader": "r.py"}})
    src = LB.specimen(m, "probe", "s", [LB.q("a")], {"x": b"0123456789"})
    r = ctf(tmp_path, "scale", str(src), str(m / "probe" / "big"), "--bytes", "25")
    assert r.returncode == 0, r.stderr
    assert "30 bytes in 3 member(s), 3 id(s)" in r.stdout
    r = ctf(tmp_path, "scale", str(src), str(m / "probe" / "big"), "--bytes", "25")
    assert r.returncode == 2 and "already exists" in r.stderr
