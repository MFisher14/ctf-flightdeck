"""B-041: intake auto-runs the fast lane on welcome / zero-file / platform-profile challenges.

A welcome challenge that prints its flag in the brief is `solved` by intake (the flag is kept, not
dropped as brief-quoted template text); a profile challenge with no inline flag records the human step
and stays `none`; a normal challenge still drops a brief-quoted flag (the auto-trigger must not fire on
it). The platform is a tiny fake adapter and no engines run (manifests=[]); nothing is submitted.

Run:  .venv/bin/python -m pytest tests/test_intake_welcome.py
"""
from __future__ import annotations

import json
from pathlib import Path

from ctf import event
from ctf import intake as I
from ctf.platform.base import Challenge, FileRef, PlatformError

CSCTF = event.load("csctf")
FLAG = "CSCTF{w3lc0me_ab0ard}"


class FakeAdapter:
    kind = "fake"

    def __init__(self, challenges):
        self.challenges = challenges          # id -> (Challenge, {relpath: bytes})
        self.submits = []

    def list_challenges(self):
        return [c for c, _ in self.challenges.values()]

    def get_challenge(self, cid):
        if cid not in self.challenges:
            raise PlatformError(f"get_challenge({cid}): 404")
        return self.challenges[cid][0]

    def download_files(self, cid, dest):
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


def _ch(cid, name="Chal", category="misc", description="", points=10, files=()):
    return Challenge(id=cid, name=name, category=category, points=points, description=description,
                     files=tuple(FileRef(f) for f in files), solved_by_team=False)


def _intake(wd, ad, cid):
    opts = I.Options(engines=False, net_guard="hook")
    return I.intake_one(cid, CSCTF, adapter=ad, workdir=wd, options=opts, manifests=[])


def _report(rep):
    return json.loads((rep.dir / I.REPORT).read_text())


def test_zero_file_welcome_challenge_with_an_inline_flag_is_solved(tmp_path):
    ad = FakeAdapter({"9090": (_ch("9090", "Welcome Aboard", "misc",
                                   f"Welcome to the CTF! Your first flag is {FLAG}. Enjoy."), {})})
    rep = _intake(tmp_path / "wd", ad, "9090")
    assert rep.status == "solved", (rep.status, rep.notes)
    assert rep.result.flags == (FLAG,)
    assert FLAG not in rep.excluded                     # the brief flag was kept, not dropped
    assert rep.welcome and rep.welcome["flag"] == FLAG and rep.welcome["klass"] == "welcome"
    assert any("fastlane welcome" in n for n in rep.notes)
    assert ad.submits == []
    j = _report(rep)
    assert j["status"] == "solved" and j["welcome"]["flag"] == FLAG
    assert any("fastlane welcome" in w for w in rep.flags[FLAG])


def test_a_normal_challenge_still_drops_a_brief_quoted_flag(tmp_path):
    # the auto-trigger must fire only on the welcome/profile classes: a crypto challenge quoting the
    # format in its brief is unchanged -- the brief value is still excluded as template text.
    ad = FakeAdapter({"42": (_ch("42", "RSA Warmup", "crypto", f"Decrypt it. Format: {FLAG}"), {})})
    rep = _intake(tmp_path / "wd", ad, "42")
    assert rep.welcome is None
    assert rep.status == "none"
    assert FLAG not in rep.result.flags


def test_a_normal_challenge_quoting_the_rules_wording_does_not_force_promote_its_brief_flag(tmp_path):
    # B-041 finding 2: a non-welcome challenge whose brief merely contains "the rules" next to exactly
    # one flag-shaped value must NOT be classed sanity and have that value force-promoted to a confirmed
    # solve. The class signal is the name/category, not loose description prose.
    ad = FakeAdapter({"77": (_ch("77", "Scope Recon", "forensics",
                                 f"Per the rules, stay in scope. One capture holds {FLAG}."), {})})
    rep = _intake(tmp_path / "wd", ad, "77")
    assert rep.welcome is None                           # not classed welcome/sanity
    assert rep.status == "none" and FLAG not in rep.result.flags
    assert FLAG in rep.excluded                          # the brief value stays excluded as template text


def test_platform_profile_challenge_records_the_human_step_and_finds_no_flag(tmp_path):
    ad = FakeAdapter({"17": (_ch("17", "Where U From", "misc",
                                 "Update your team profile with your country and the flag appears."), {})})
    rep = _intake(tmp_path / "wd", ad, "17")
    assert rep.welcome and rep.welcome["klass"] == "platform-profile" and rep.welcome["flag"] is None
    assert rep.status == "none" and rep.result.flags == ()
    assert any("human step" in n and "profile" in n for n in rep.notes)
    # the base_url in the human step comes from the event profile, not a hardcoded host
    assert rep.welcome["instruction"] and "by hand" in rep.welcome["instruction"]


def test_welcome_flag_is_solved_even_though_the_sweep_sees_it_in_a_handout_too(tmp_path):
    # the flag is both in the brief and in a handout file: it must still be one `solved` flag, and the
    # welcome provenance recorded alongside the sweep's.
    ad = FakeAdapter({"9091": (_ch("9091", "Welcome", "misc",
                                   f"Welcome! The flag is {FLAG}.", files=("readme.txt",)),
                               {"readme.txt": f"hello {FLAG}\n".encode()})})
    rep = _intake(tmp_path / "wd", ad, "9091")
    assert rep.status == "solved" and rep.result.flags == (FLAG,)
    assert FLAG not in rep.excluded


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
