"""B-181: the shared per-challenge hypothesis ledger (ctf/hypothesis.py, ctf/cli/hypothesis.py).

Offline. Every test drives the real module against a tmp workdir; the flag-format checks use the real
csctf profile. No network, no model, no challenge files.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time

import pytest

from ctf import env, event, paths
from ctf import hypothesis as hyp
from ctf.cli import hypothesis as cli


@pytest.fixture
def wd(tmp_path):
    return tmp_path / "work"


@pytest.fixture
def csctf():
    return event.load("csctf")


# ------------------------------------------------------------------------------- record + read

def test_record_round_trips_with_every_schema_field(wd):
    rec = hyp.record("12", hypothesis="LSB in blue", method="zsteg -a", result=hyp.NEGATIVE,
                     family="rk", agent="codex-3", evidence="no flag-shaped output", workdir=wd)
    (got,) = hyp.entries("12", wd)
    assert got == rec
    for k in ("ts", "challenge_id", "hypothesis", "method", "method_key", "result",
              "payload", "family", "agent", "evidence", "control", "verified"):
        assert k in got
    assert got["challenge_id"] == "12" and got["agent"] == "codex-3" and got["result"] == "negative"


def test_two_agents_append_without_losing_either(wd):
    hyp.record("7", hypothesis="h1", method="m1", result=hyp.NEGATIVE, agent="a1", workdir=wd)
    hyp.record("7", hypothesis="h2", method="m2", result=hyp.INCONCLUSIVE, agent="a2", workdir=wd)
    recs = hyp.entries("7", wd)
    assert [r["agent"] for r in recs] == ["a1", "a2"]
    assert [r["method"] for r in recs] == ["m1", "m2"]


def test_default_agent_is_unknown_not_omitted(wd):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.ERROR, workdir=wd)
    assert rec["agent"] == "unknown"


def test_each_challenge_has_its_own_file(wd):
    hyp.record("A", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    hyp.record("B", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    assert hyp.path("A", wd) != hyp.path("B", wd)
    assert len(hyp.entries("A", wd)) == 1 and len(hyp.entries("B", wd)) == 1


# -------------------------------------------------------------------------------- validation of input

def test_empty_challenge_id_is_rejected(wd):
    with pytest.raises(hyp.HypothesisError):
        hyp.record("  ", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)


def test_empty_method_is_rejected(wd):
    with pytest.raises(hyp.HypothesisError):
        hyp.record("1", hypothesis="h", method="   ", result=hyp.NEGATIVE, workdir=wd)


def test_result_outside_the_vocabulary_is_rejected(wd):
    with pytest.raises(hyp.HypothesisError):
        hyp.record("1", hypothesis="h", method="m", result="maybe", workdir=wd)


def test_corrupt_line_raises_not_skips(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    p = hyp.path("1", wd)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    with pytest.raises(hyp.HypothesisError):
        hyp.entries("1", wd)


# --------------------------------------------------------------------------- method keys / dedupe

def test_method_key_collapses_case_and_whitespace(wd):
    hyp.record("1", hypothesis="h", method="zsteg -a", result=hyp.NEGATIVE, agent="a1", workdir=wd)
    # same probe written differently must resolve to the same record
    found = hyp.seen("1", "ZSTEG   -a", wd)
    assert found is not None and found["agent"] == "a1"


def test_normalize_method_rejects_empty():
    with pytest.raises(hyp.HypothesisError):
        hyp.normalize_method("   ")


# ------------------------------------------------------------------------------------ should_skip

def test_should_skip_false_when_never_tried(wd):
    s = hyp.should_skip("1", "never", wd)
    assert s.skip is False and s.prior is None and "not tried" in s.reason


def test_should_skip_true_on_a_negative(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.NEGATIVE, agent="a1", workdir=wd)
    s = hyp.should_skip("1", "m", wd)
    assert s.skip is True and "negative" in s.reason and "a1" in s.reason


def test_should_skip_true_on_a_verified_positive(wd, csctf):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               payload="csctf{found_it}", workdir=wd, profile=csctf)
    assert hyp.should_skip("1", "m", wd).skip is True


def test_should_skip_false_on_an_unverified_positive(wd, csctf):
    # a brute hit with a non-flag payload and no control: NOT settled, must be re-confirmed
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               payload="deadbeef", workdir=wd, profile=csctf)
    s = hyp.should_skip("1", "m", wd)
    assert s.skip is False and "unverified" in s.reason


def test_should_skip_false_on_error_and_inconclusive(wd):
    hyp.record("1", hypothesis="h", method="e", result=hyp.ERROR, workdir=wd)
    hyp.record("1", hypothesis="h", method="i", result=hyp.INCONCLUSIVE, workdir=wd)
    assert hyp.should_skip("1", "e", wd).skip is False
    assert hyp.should_skip("1", "i", wd).skip is False


def test_latest_result_wins_a_later_record_overrides(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.ERROR, workdir=wd)
    hyp.record("1", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    assert hyp.methods_tried("1", wd)["m"] == hyp.NEGATIVE
    assert hyp.should_skip("1", "m", wd).skip is True


# ---------------------------------------------------------------------------- positive control

def test_positive_with_explicit_control_is_verified(wd):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
                     payload="whatever", control="decoded against the known crib", workdir=wd)
    assert rec["verified"] is True and "control" in rec["verify_reason"]


def test_positive_with_flag_payload_is_verified(wd, csctf):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
                     payload="csctf{abc_123}", workdir=wd, profile=csctf)
    assert rec["verified"] is True


def test_positive_with_junk_payload_and_no_control_is_unverified(wd, csctf):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
                     payload="deadbeef", workdir=wd, profile=csctf)
    assert rec["verified"] is False and "false positive" in rec["verify_reason"]


def test_positive_with_no_payload_and_no_control_is_unverified(wd):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE, workdir=wd)
    assert rec["verified"] is False


def test_validate_positive_degrades_loudly_without_a_flag_format():
    # no profile and no resolvable event -> cannot check the payload, but never silently verified
    c = hyp.validate_positive("deadbeef", None, profile=None)
    assert c.verified is False and c.reason


def test_non_positive_results_are_never_verified(wd):
    rec = hyp.record("1", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    assert rec["verified"] is False and "verify_reason" not in rec


# ------------------------------------------------------------------------- false positives

def test_mark_false_positive_records_a_correction(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               payload="x", family="rk", agent="a1", workdir=wd)
    rec = hyp.mark_false_positive("1", "M", agent="a2", workdir=wd)   # case-insensitive method match
    assert rec["result"] == hyp.FALSE_POSITIVE and rec["family"] == "rk"
    assert hyp.methods_tried("1", wd)["m"] == hyp.FALSE_POSITIVE


def test_mark_false_positive_without_a_prior_positive_raises(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    with pytest.raises(hyp.HypothesisError):
        hyp.mark_false_positive("1", "m", workdir=wd)


def test_false_positive_rate_counts_across_challenges(wd):
    # family rk: two challenges go positive, one is later corrected -> 50%
    hyp.record("A", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", family="rk", workdir=wd)
    hyp.record("B", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", family="rk", workdir=wd)
    hyp.mark_false_positive("B", "m", workdir=wd)
    r = hyp.false_positive_rate("rk", wd)
    assert (r.positives, r.false_positives, r.rate) == (2, 1, 0.5)


def test_false_positive_rate_unknown_family_is_no_data(wd):
    hyp.record("A", hypothesis="h", method="m", result=hyp.NEGATIVE, family="rk", workdir=wd)
    r = hyp.false_positive_rate("rk", wd)
    assert r.positives == 0 and r.rate is None   # no positives yet -> None, never 0.0


def test_a_false_positive_without_a_matching_positive_is_not_counted(wd):
    # a correction only counts against a method that actually went positive in that family
    hyp.record("A", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", family="rk", workdir=wd)
    hyp.record("A", hypothesis="h", method="other", result=hyp.FALSE_POSITIVE, family="rk", workdir=wd)
    r = hyp.false_positive_rate("rk", wd)
    assert r.positives == 1 and r.false_positives == 0


def test_families_sorts_worst_rate_first(wd):
    hyp.record("A", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", family="good", workdir=wd)
    hyp.record("B", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", family="bad", workdir=wd)
    hyp.mark_false_positive("B", "m", workdir=wd)
    fams = hyp.families(wd)
    assert [f.family for f in fams] == ["bad", "good"]


# ------------------------------------------------------------------------------------ the miner

def test_mine_returns_the_verified_positive(wd, csctf):
    hyp.record("1", hypothesis="junk", method="brute", result=hyp.POSITIVE,
               payload="deadbeef", workdir=wd, profile=csctf)          # unverified
    hyp.record("1", hypothesis="real mechanism", method="xor key", result=hyp.POSITIVE,
               payload="csctf{the_real_one}", agent="a9", workdir=wd, profile=csctf)
    m = hyp.mine("1", wd)
    assert m is not None and m.method == "xor key" and m.payload == "csctf{the_real_one}"
    assert m.hypothesis == "real mechanism" and m.agent == "a9"


def test_mine_is_none_without_a_verified_positive(wd, csctf):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               payload="deadbeef", workdir=wd, profile=csctf)
    assert hyp.mine("1", wd) is None


def test_mine_excludes_a_corrected_positive(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               control="looked right", workdir=wd)                     # verified by control
    hyp.mark_false_positive("1", "m", workdir=wd)                      # but it was wrong
    assert hyp.mine("1", wd) is None


def test_mine_all_one_mechanism_per_solved_challenge(wd, csctf):
    hyp.record("A", hypothesis="ha", method="m", result=hyp.POSITIVE,
               payload="csctf{abc}", workdir=wd, profile=csctf)
    hyp.record("B", hypothesis="hb", method="m", result=hyp.POSITIVE,
               payload="deadbeef", workdir=wd, profile=csctf)          # unverified: not mined
    ms = hyp.mine_all(wd)
    assert {m.challenge_id for m in ms} == {"A"}


def test_file_mechanism_round_trips(wd, csctf):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE, payload="csctf{found}",
               family="rk", control="decoder recovers the planted test flag", workdir=wd, profile=csctf)
    m = hyp.mine("1", wd)
    hyp.file_mechanism(m, wd)
    (filed,) = hyp.mechanisms(wd)
    assert filed["challenge_id"] == "1" and filed["payload"] == "csctf{found}" and filed["family"] == "rk"
    assert filed["verified_by"] == hyp.VERIFIED_BY_CONTROL


def test_mechanisms_file_is_not_read_as_a_challenge(wd, csctf):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE,
               payload="csctf{found}", workdir=wd, profile=csctf)
    hyp.file_mechanism(hyp.mine("1", wd), wd)
    # the _mechanisms.jsonl file must not appear as a challenge in family/mine_all scans
    assert len(hyp.mine_all(wd)) == 1


# ------------------------------------------------------------------------------------ the CLI

def _args(**kw):
    ns = argparse.Namespace(event=None, workdir=None, json=False)
    ns.__dict__.update(kw)
    return ns


def test_cli_check_exit_codes(wd, capsys):
    hyp.record("12", hypothesis="h", method="zsteg -a", result=hyp.NEGATIVE, workdir=wd)
    assert cli.run(_args(action="check", cid="12", method="ZSTEG -a", workdir=str(wd))) == 1  # skip
    assert cli.run(_args(action="check", cid="12", method="other", workdir=str(wd))) == 0     # run
    out = capsys.readouterr().out
    assert "SKIP" in out and "RUN" in out


def test_cli_record_then_list(wd, capsys):
    rc = cli.run(_args(action="record", cid="5", hypothesis="LSB", method="zsteg",
                       result="negative", payload=None, family=None, agent="a1",
                       evidence="", control=None, workdir=str(wd)))
    assert rc == 0
    capsys.readouterr()
    assert cli.run(_args(action="list", cid="5", workdir=str(wd))) == 0
    assert "zsteg" in capsys.readouterr().out


def test_cli_false_and_fp(wd, capsys):
    cli.run(_args(action="record", cid="5", hypothesis="h", method="m", result="positive",
                  payload="x", family="rk", agent="a1", evidence="", control="looked right",
                  workdir=str(wd)))
    capsys.readouterr()
    assert cli.run(_args(action="false", cid="5", method="m", agent="a2", evidence="",
                         workdir=str(wd))) == 0
    capsys.readouterr()
    assert cli.run(_args(action="fp", family="rk", workdir=str(wd))) == 0
    assert "100%" in capsys.readouterr().out


def test_cli_false_without_positive_returns_2(wd, capsys):
    cli.run(_args(action="record", cid="5", hypothesis="h", method="m", result="negative",
                  payload=None, family=None, agent=None, evidence="", control=None, workdir=str(wd)))
    capsys.readouterr()
    rc = cli.run(_args(action="false", cid="5", method="m", agent=None, evidence="", workdir=str(wd)))
    assert rc == 2
    assert "ctf hypothesis:" in capsys.readouterr().err


def test_cli_mine_file_writes_back(wd, capsys):
    cli.run(_args(action="record", cid="5", hypothesis="h", method="m", result="positive",
                  payload="x", family=None, agent=None, evidence="", control="good",
                  workdir=str(wd)))
    capsys.readouterr()
    assert cli.run(_args(action="mine", cid="5", file=True, workdir=str(wd))) == 0
    assert hyp.mechanisms(wd)


# ---------------------------------------------------- round 1 fixes: brute garbage is never verified

@pytest.fixture
def pink():
    return event.load("pink")


def test_flag_shaped_binary_garbage_is_unverified(wd, pink):
    # pink's body is [^{}\n]{1,256}: PINK{ + raw bytes + } matches the flag regex. It must not verify.
    garbage = "PINK{\x8a\x13\x07\xfe}"
    rec = hyp.record("wn", hypothesis="LSB", method="bitplane brute", result=hyp.POSITIVE,
                     payload=garbage, workdir=wd, profile=pink)
    assert rec["verified"] is False and rec["verified_by"] is None
    assert "non-printable" in rec["verify_reason"]
    assert hyp.should_skip("wn", "bitplane brute", wd).skip is False
    assert hyp.mine("wn", wd) is None


def test_flag_shaped_latin1_garbage_is_unverified(pink):
    # every char printable, but bytes decoded as latin-1 (\xfe\xff) are not a plausible flag body
    c = hyp.validate_positive("PINK{þÿé}", None, profile=pink)
    assert c.verified is False and c.by is None


def test_printable_flag_without_family_is_verified_by_flag_format(wd, pink):
    rec = hyp.record("wn", hypothesis="h", method="read the comment", result=hyp.POSITIVE,
                     payload="PINK{white_noise}", workdir=wd, profile=pink)
    assert rec["verified"] is True and rec["verified_by"] == hyp.VERIFIED_BY_FLAG


def test_brute_family_hit_needs_an_explicit_control(wd, pink):
    # even a clean, printable flag from a brute family is not verified by its shape alone
    rec = hyp.record("wn", hypothesis="h", method="rockyou lsb", result=hyp.POSITIVE,
                     payload="PINK{looks_fine}", family="rockyou-lsb", workdir=wd, profile=pink)
    assert rec["verified"] is False and "brute-family" in rec["verify_reason"]
    assert hyp.should_skip("wn", "rockyou lsb", wd).skip is False
    rec2 = hyp.record("wn", hypothesis="h", method="rockyou lsb", result=hyp.POSITIVE,
                      payload="PINK{looks_fine}", family="rockyou-lsb",
                      control="same extractor recovers a planted PINK{test} from a synthetic image",
                      workdir=wd, profile=pink)
    assert rec2["verified"] is True and rec2["verified_by"] == hyp.VERIFIED_BY_CONTROL
    assert "attested" in rec2["verify_reason"]
    assert hyp.should_skip("wn", "rockyou lsb", wd).skip is True


# ----------------------------------------------------------- round 1 fixes: corrections and miner

def test_mark_false_positive_takes_family_from_the_positive_it_corrects(wd):
    hyp.record("1", hypothesis="key is rockyou", method="m", result=hyp.POSITIVE, payload="x",
               family="rk", workdir=wd)
    hyp.record("1", hypothesis="later retry", method="m", result=hyp.NEGATIVE, workdir=wd)   # no family
    rec = hyp.mark_false_positive("1", "m", workdir=wd)
    assert rec["family"] == "rk" and rec["hypothesis"] == "key is rockyou"
    r = hyp.false_positive_rate("rk", wd)
    assert (r.positives, r.false_positives, r.rate) == (1, 1, 1.0)


def test_should_skip_after_a_false_positive_skips(wd):
    hyp.record("1", hypothesis="h", method="m", result=hyp.POSITIVE, payload="x", workdir=wd)
    assert hyp.should_skip("1", "m", wd).skip is False          # unverified positive: re-confirm
    hyp.mark_false_positive("1", "m", agent="a2", workdir=wd)
    s = hyp.should_skip("1", "m", wd)
    assert s.skip is True and s.prior["result"] == hyp.FALSE_POSITIVE
    assert hyp.FALSE_POSITIVE in s.reason and "a2" in s.reason


def test_mine_picks_the_latest_of_two_verified_positives(wd, csctf):
    hyp.record("1", hypothesis="first", method="m1", result=hyp.POSITIVE,
               payload="csctf{first}", workdir=wd, profile=csctf)
    hyp.record("1", hypothesis="second", method="m2", result=hyp.POSITIVE,
               payload="csctf{second}", workdir=wd, profile=csctf)
    m = hyp.mine("1", wd)
    assert m is not None and m.method == "m2" and m.payload == "csctf{second}"
    assert m.verified_by == hyp.VERIFIED_BY_FLAG


# ------------------------------------------------------------- round 1 fixes: concurrent writers

_CHILD = (
    "import sys\n"
    "from pathlib import Path\n"
    "from ctf import hypothesis as h\n"
    "wd, agent, n = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])\n"
    "print('ready', flush=True)\n"
    "for i in range(n):\n"
    "    h.record('7', hypothesis='h' * 300, method=f'{agent}-{i}', result='negative',\n"
    "             agent=agent, evidence='e' * 3000, workdir=wd)\n"
    "print('done', flush=True)\n"
)


def _child(wd, agent, n):
    return subprocess.Popen([sys.executable, "-c", _CHILD, str(wd), agent, str(n)],
                            cwd=paths.repo_root(), stdout=subprocess.PIPE, text=True)


def test_append_waits_for_a_writer_holding_the_lock(wd):
    # another agent (a separate process) holding the ledger lock must block our append until released
    hyp.record("7", hypothesis="h0", method="m0", result=hyp.NEGATIVE, agent="a0", workdir=wd)
    fd = os.open(hyp.path("7", wd), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    child = None
    try:
        child = _child(wd, "child", 1)
        assert child.stdout.readline().strip() == "ready"
        time.sleep(1.0)
        assert child.poll() is None, "the append did not wait for the lock"
        assert [r["agent"] for r in hyp.entries("7", wd)] == ["a0"]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        if child is not None and child.poll() is None:
            try:
                child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                raise
    assert child.returncode == 0 and child.stdout.read().strip() == "done"
    assert [r["agent"] for r in hyp.entries("7", wd)] == ["a0", "child"]


def test_concurrent_processes_append_every_line_intact(wd):
    n, agents = 40, ["p1", "p2", "p3", "p4"]
    kids = [_child(wd, a, n) for a in agents]
    for k in kids:
        out, _ = k.communicate(timeout=120)
        assert k.returncode == 0 and out.split()[-1] == "done"
    recs = hyp.entries("7", wd)                  # raises HypothesisError on an interleaved line
    assert len(recs) == n * len(agents)
    for a in agents:
        assert [r["method"] for r in recs if r["agent"] == a] == [f"{a}-{i}" for i in range(n)]


# ------------------------------------------------------------- round 1 fixes: CLI --event handling

def _record_args(**kw):
    base = dict(action="record", cid="5", hypothesis="h", method="m", result="positive",
                payload="csctf{abc}", family=None, agent=None, evidence="", control=None)
    base.update(kw)
    return _args(**base)


def test_cli_unknown_event_exits_2_and_writes_nothing(wd, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert cli.run(_record_args(event="nosuch", workdir=str(wd))) == 2
    assert "nosuch" in capsys.readouterr().err
    assert not hyp.path("5", wd).exists()
    # without --workdir the ledger would land under the (unvalidated) slug's workdir: still refused
    alt = tmp_path / "envwork"
    monkeypatch.setenv("CTF_WORKDIR", str(alt))
    assert cli.run(_record_args(event="nosuch")) == 2
    assert not alt.exists()
    # read-only actions refuse it too, rather than answering from a workdir no event owns
    hyp.record("5", hypothesis="h", method="m", result=hyp.NEGATIVE, workdir=wd)
    assert cli.run(_args(action="check", cid="5", method="m", event="nosuch", workdir=str(wd))) == 2
    assert cli.run(_args(action="list", cid="5", event="nosuch", workdir=str(wd))) == 2


def test_cli_explicit_event_selects_its_flag_format(wd, monkeypatch):
    # CTF_EVENT says pink, --event says csctf: csctf{...} must be checked against csctf's format
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert cli.run(_record_args(event="csctf", workdir=str(wd))) == 0
    (rec,) = hyp.entries("5", wd)
    assert rec["verified"] is True and rec["verified_by"] == hyp.VERIFIED_BY_FLAG


def test_cli_no_resolvable_event_records_unverified_with_reason(wd, monkeypatch):
    for name in ("CTF_EVENT", *env.legacy_names("CTF_EVENT")):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(event.EventError):
        event.current()                          # precondition: several profiles, none selected
    assert cli.run(_record_args(workdir=str(wd))) == 0
    (rec,) = hyp.entries("5", wd)
    assert rec["verified"] is False and "unavailable" in rec["verify_reason"]


# ------------------------------------------------- round 2 fixes: the correction targets the LATEST positive

def test_mark_false_positive_corrects_the_latest_of_two_positives(wd):
    # two positives on one method from different families/hypotheses: the correction is for the latest
    hyp.record("1", hypothesis="h1 rockyou key", method="m", result=hyp.POSITIVE, payload="x",
               family="a", workdir=wd)
    hyp.record("1", hypothesis="h2 crackstation key", method="m", result=hyp.POSITIVE, payload="y",
               family="b", workdir=wd)
    rec = hyp.mark_false_positive("1", "m", workdir=wd)
    assert rec["family"] == "b" and rec["hypothesis"] == "h2 crackstation key"
    rb = hyp.false_positive_rate("b", wd)
    assert (rb.positives, rb.false_positives, rb.rate) == (1, 1, 1.0)
    ra = hyp.false_positive_rate("a", wd)
    assert (ra.positives, ra.false_positives, ra.rate) == (1, 0, 0.0)


# --------------------------------------- round 2 fixes: printable junk is not a plausible flag body

@pytest.mark.parametrize("junk", ["PINK{#%!@(*&^}", "PINK{ }", "PINK{   }", "PINK{ab}", "PINK{a!b}",
                                  "PINK{abc!?!?}"])
def test_printable_junk_flag_body_is_unverified(wd, pink, junk):
    rec = hyp.record("wn", hypothesis="h", method="read it", result=hyp.POSITIVE,
                     payload=junk, workdir=wd, profile=pink)
    assert rec["verified"] is False and rec["verified_by"] is None
    assert "implausible" in rec["verify_reason"]
    assert hyp.should_skip("wn", "read it", wd).skip is False      # not settled
    assert hyp.mine("wn", wd) is None                               # never filed as the mechanism


@pytest.mark.parametrize("ok", ["PINK{abc}",         # exactly MIN_BODY_WORD_CHARS word characters
                                "PINK{abc!?!}",      # exactly MIN_BODY_WORD_RATIO (3/6)
                                "PINK{y0u_g0t_!t}",  # leet with a symbol
                                "PINK{the quick fox}"])
def test_plausible_flag_bodies_still_verify_by_flag_format(pink, ok):
    c = hyp.validate_positive(ok, None, profile=pink)
    assert c.verified is True and c.by == hyp.VERIFIED_BY_FLAG, c.reason


def test_hex_flag_body_verifies_by_flag_format():
    c = hyp.validate_positive("flag{" + "0123456789abcdef" * 2 + "}", None,
                              profile=event.load("huntress"))
    assert c.verified is True and c.by == hyp.VERIFIED_BY_FLAG


def test_body_implausible_names_the_reason():
    assert "word character" in hyp.body_implausible("PINK{ }")
    assert "mostly symbols" in hyp.body_implausible("PINK{#%!@(*&^abc}")
    assert hyp.body_implausible("PINK{white_noise}") is None
    assert hyp.flag_body("  PINK{a{b}  ") == "a{b"


# ------------------------------------- round 2 fixes: a correction only covers positives before it

def test_mine_takes_a_verified_positive_recorded_after_a_correction(wd):
    hyp.record("1", hypothesis="wrong key", method="m", result=hyp.POSITIVE,
               control="looked right", agent="a1", workdir=wd)
    hyp.mark_false_positive("1", "m", workdir=wd)
    assert hyp.mine("1", wd) is None
    hyp.record("1", hypothesis="right key", method="m", result=hyp.POSITIVE, payload="p",
               control="same extractor recovers a planted flag", agent="a2", workdir=wd)
    m = hyp.mine("1", wd)
    assert m is not None and m.hypothesis == "right key" and m.agent == "a2"


def test_mine_a_correction_on_one_method_keeps_another_methods_positive(wd):
    hyp.record("1", hypothesis="real", method="n", result=hyp.POSITIVE, control="ok", workdir=wd)
    hyp.record("1", hypothesis="wrong", method="m", result=hyp.POSITIVE, control="ok", workdir=wd)
    hyp.mark_false_positive("1", "m", workdir=wd)
    m = hyp.mine("1", wd)
    assert m is not None and m.method == "n" and m.hypothesis == "real"
