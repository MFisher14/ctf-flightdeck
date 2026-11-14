"""B-119: the constructed-marker engine and intake's auto-submit (B-002).

Intake takes an engine's flags whatever the engine's result status, and one distinct flag makes the
intake `solved`, which `ctf intake --submit` may send. This engine's flags are guesses: a convention
the judge accepted for ANOTHER challenge of the family (the shipped seed holds three), or a prior. So
the engine has no `[intake]` table: the router lists it for the agent and intake never runs it.

These tests drive the real `intake_one` with the engine's real manifest and the shipped seed, on
synthetic handouts served by a fake adapter (no platform, no network). The first handout is the one
that showed the defect: its fields carry the role names of the seeded networking convention, so the
engine answers with exactly one flag.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import labels
import marker_convention as mc
from ctf import event, paths
from ctf import intake as I
from ctf.engines import manifest
from ctf.intake import autosubmit
from ctf.platform.base import Challenge, FileRef

MANIFEST = paths.repo_root() / "solvers" / "common" / "marker_convention.manifest.toml"
CSCTF = event.load("csctf")
IMSI, SESSION, EPOCH = "901700000012345", "hss.example.test;1893456789;40404", 1893456789
GUESS = "CSCTF{" + hashlib.sha256(f"{IMSI}:{SESSION}:{EPOCH}".encode()).hexdigest()[:8] + "}"
MARKER_BRIEF = ("Trace the roaming fraud through the subscriber records, then recover its marker.\n\n"
                "Flag format: **`CSCTF{8_lowercase_hex}`**")


class Adapter:
    """A platform that serves one synthetic challenge and must never be sent anything."""
    kind = "fake"

    def __init__(self, challenge: Challenge, files: dict):
        self.challenge, self.files = challenge, files

    def get_challenge(self, cid):
        return self.challenge

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            path = Path(dest) / rel
            path.write_bytes(data)
            out.append(path)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake must never submit")


@pytest.fixture(autouse=True)
def _shipped_seed(tmp_path, monkeypatch):
    """The knowledge base as the repo ships it, with an empty runtime ledger."""
    for name in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    labels._cache.clear()
    yield
    labels._cache.clear()


def intake(tmp_path, cid, category, brief, files):
    ch = Challenge(id=cid, name="Synthetic Case", category=category, points=300, description=brief,
                   files=tuple(FileRef(f) for f in files), solved_by_team=False)
    return I.intake_one(cid, CSCTF, adapter=Adapter(ch, files), workdir=tmp_path / "wd",
                        options=I.Options(net_guard="hook", record=False),
                        manifests=[manifest.load(MANIFEST)])


def telecom_files() -> dict:
    return {"subscriber.json": json.dumps({"imsi": IMSI, "session_id": SESSION, "epoch": EPOCH}).encode(),
            "trace.log": f"imsi = {IMSI}\nsession_id = {SESSION}\nepoch = {EPOCH}\n".encode()}


def test_intake_never_runs_the_engine_so_its_one_guess_is_never_auto_submittable(tmp_path):
    rep = intake(tmp_path, "7001", "Network", MARKER_BRIEF, telecom_files())
    # the engine WOULD answer with exactly one flag here: a guess from a convention learned elsewhere
    res = mc.solve(rep.dir, CSCTF, budget=2000)
    assert (res.status, res.flags) == ("candidate", (GUESS,))
    assert autosubmit.eligible("solved", res.flags, CSCTF)[0] == GUESS      # what intake would have made of it
    # intake did not run it: the challenge is not solved, there is no flag, nothing is eligible
    assert rep.status == "none" and rep.flags == {} and rep.result.flags == ()
    assert [r.engine for r in rep.runs] == []
    assert autosubmit.eligible(rep.status, rep.result.flags, CSCTF)[0] is None
    # it is listed for the agent as routed here, with the phrase that routed it
    listed = rep.to_dict()["engines_without_adapter"]
    assert [e["engine"] for e in listed] == ["common.marker_convention"] and "recover its marker" in listed[0]["why"]
    assert (rep.dir / I.FLAGS).read_text(encoding="utf-8") == ""           # the flags-found file holds no guess


def test_a_flag_in_the_clear_is_still_one_unambiguous_flag_beside_hex_shape_wording(tmp_path):
    flag = "CSCTF{" + hashlib.md5(b"a synthetic dropped file").hexdigest() + "}"
    files = dict(telecom_files())
    files["readme.txt"] = f"recovered from the dropper: {flag}\n".encode()
    brief = "Find the dropped file. Flag format: CSCTF{32_lowercase_hex} (32 lowercase hex characters)."
    rep = intake(tmp_path, "7002", "Forensics", brief, files)
    assert rep.status == "solved" and list(rep.flags) == [flag]
    assert autosubmit.eligible(rep.status, rep.result.flags, CSCTF)[0] == flag
    assert [r.engine for r in rep.runs] == [] and rep.to_dict()["engines_without_adapter"] == []
