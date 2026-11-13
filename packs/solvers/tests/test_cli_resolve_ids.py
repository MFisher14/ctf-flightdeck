"""B-010: python -m ctf resolve-ids (exit 0 all resolved, 1 fail closed, 2 unusable input)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from ctf import paths

CONV = str(paths.repo_root() / "solvers" / "binary" / "id_conventions.toml")


def run_ctf(tmp_path, *args):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="csctf")
    return subprocess.run([sys.executable, "-m", "ctf", "resolve-ids", *args], cwd=paths.repo_root(), env=e,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)


def dump(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
    return str(p)


def test_all_resolved_exits_0(tmp_path):
    status = {"questions": [{"id": "set1.slot0_entry_point"}, {"id": "set1.c_sha256"}, {"id": "url"}]}
    r = run_ctf(tmp_path, dump(tmp_path, "status.json", status), "--conventions", CONV)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert "set1.slot0_entry_point -> d01_analysis_entry_point (scope-field) [slot 0]" in lines
    assert "set1.c_sha256 -> d01_artifact_sha256_1 (scope-alias) [c]" in lines
    assert lines[-1].startswith("resolved 3 of 3")


def test_unmatched_fails_closed_with_exit_1(tmp_path):
    r = run_ctf(tmp_path, dump(tmp_path, "q.json", ["slot0_entry_point", "slot0_new_field"]), "--conventions", CONV,
                "--json")
    assert r.returncode == 1
    rep = json.loads(r.stdout)
    assert rep["ok"] is False and rep["counts"]["unmatched"] == 1
    assert [x["status"] for x in rep["resolutions"]] == ["mapped", "unmatched"]


def test_attempt_known_ids_and_member_stems(tmp_path):
    base = {"questions": [{"id": "evidence-note-filename"}, {"id": "md5"}, {"id": "filename"}]}
    q = ["roster-md5", "evidence-note-filename"]
    r = run_ctf(tmp_path, dump(tmp_path, "q.json", q), "--attempt", dump(tmp_path, "attempt.json", base),
                "--member", "roster.csv")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "roster-md5 -> md5 (stem) [file roster.csv]" in r.stdout
    # two delivered files with the stem: ambiguous, exit 1
    d = tmp_path / "members"
    d.mkdir()
    (d / "roster.csv").write_bytes(b"")
    (d / "roster.txt").write_bytes(b"")
    r = run_ctf(tmp_path, dump(tmp_path, "q2.json", ["roster-md5"]), "--known-ids",
                dump(tmp_path, "known.txt", "# fields\nmd5\nfilename\n"), "--members-dir", str(d))
    assert r.returncode == 1 and "AMBIGUOUS" in r.stdout and "FAIL CLOSED" in r.stdout


def test_unusable_input_exits_2(tmp_path):
    q = dump(tmp_path, "q.json", ["a"])
    r = run_ctf(tmp_path, q)
    assert r.returncode == 2 and "no catalog" in r.stderr
    r = run_ctf(tmp_path, str(tmp_path / "missing.json"), "--known-ids", q)
    assert r.returncode == 2 and "not found" in r.stderr
    r = run_ctf(tmp_path, q, "--conventions", str(tmp_path / "nope.toml"))
    assert r.returncode == 2 and "convention file not found" in r.stderr
    r = run_ctf(tmp_path, dump(tmp_path, "empty.json", {"questions": []}), "--known-ids", q)
    assert r.returncode == 2 and "no questions" in r.stderr
