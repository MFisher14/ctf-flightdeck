"""B-090: an engine that returns `candidate` keeps its flag a candidate through intake's roll-up.

Before, intake's `_merge` took every engine flag as confirmed whatever status the engine returned, so a
single flag from toolkits.series_chain (a computed field of a sibling's saved file, a candidate by
design) became an intake `solved` and `autosubmit.eligible` would send it. These tests drive the real
`_merge` / `_result` / `eligible` on synthetic engine runs (no engine process, no network): a flag
only a candidate engine found is `candidate` and is never eligible; a confirmed source (an engine that
did not say candidate, the sweep, a confirmed fastlane decode) still makes it `solved`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import intake as I  # noqa: E402
from ctf.intake import autosubmit, decode  # noqa: E402
from ctf.intake.engines import EngineRun  # noqa: E402
from ctf.result import SolverResult  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from series_fixtures import profile  # noqa: E402

FLAG = "CSCTF{AB:CD:EF}"


def _run(engine: str, result_status, flags=(FLAG,)) -> EngineRun:
    return EngineRun(engine=engine, inputs=(), status="ok", exit_code=0, seconds=0.1,
                     output=f"recon/engines/{engine}/out.json", errors="", result_status=result_status,
                     flags=tuple(flags))


class _SweepHit:
    method, sha256, offset = "plain", "0" * 64, None


class _Sweep:
    """The parts of a ctf.sweep.Report that _merge / _result read: one flag found in a handout file."""

    def __init__(self, flags):
        self.flags = {f: [_SweepHit()] for f in flags}
        self.excluded, self.joins = {}, []

    def _locations(self):
        return {}


def _intake(runs, *, sweep=None, fastlane=()):
    prof = profile()
    rep = I.Report("9167", None, SolverResult("none"))
    rep.runs, rep.sweep, rep.fastlane = list(runs), sweep, list(fastlane)
    I._merge(rep, prof, "Get the certificate's SHA-256 fingerprint.")
    rep.result = I._result(rep, "9167")
    return rep, prof


def test_a_flag_only_a_candidate_engine_found_stays_a_candidate_and_is_never_eligible():
    rep, prof = _intake([_run("toolkits.series_chain", "candidate")])
    assert rep.result.status == "candidate" and rep.result.flags == (FLAG,)
    assert FLAG in rep.unconfirmed and "toolkits.series_chain" in rep.unconfirmed[FLAG]
    flag, why = autosubmit.eligible(rep.result.status, rep.result.flags, prof)
    assert flag is None and "solved" in why


def test_an_engine_that_did_not_say_candidate_still_makes_one_flag_solved():
    for status in ("solved", None):        # None: the engine printed no SolverResult status
        rep, prof = _intake([_run("toolkits.other", status)])
        assert rep.result.status == "solved", status
        assert rep.unconfirmed == {}
        assert autosubmit.eligible(rep.result.status, rep.result.flags, prof)[0] == FLAG


def test_a_confirmed_engine_settles_a_candidate_engines_flag_in_either_order():
    for runs in ([_run("toolkits.series_chain", "candidate"), _run("toolkits.other", "solved")],
                 [_run("toolkits.other", "solved"), _run("toolkits.series_chain", "candidate")]):
        rep, _ = _intake(runs)
        assert rep.result.status == "solved" and rep.unconfirmed == {}


def test_the_sweep_finding_the_same_flag_settles_a_candidate_engines_flag():
    rep, _ = _intake([_run("toolkits.series_chain", "candidate")], sweep=_Sweep([FLAG]))
    assert rep.result.status == "solved" and rep.unconfirmed == {}


def test_a_confirmed_fastlane_decode_settles_a_candidate_engines_flag():
    hit = decode.Hit(flag=FLAG, chain=("b64",), source="description", reading=None,
                     verdict=decode.FLAG, why="crib-supported decode")
    rep, _ = _intake([_run("toolkits.series_chain", "candidate")], fastlane=[hit])
    assert rep.result.status == "solved" and rep.unconfirmed == {}


def test_an_unconfirmed_fastlane_decode_does_not_settle_a_candidate_engines_flag():
    hit = decode.Hit(flag=FLAG, chain=("rot13",), source="description", reading=None,
                     verdict=decode.UNCONFIRMED, why="loose steps only")
    rep, _ = _intake([_run("toolkits.series_chain", "candidate")], fastlane=[hit])
    assert rep.result.status == "candidate" and FLAG in rep.unconfirmed


def test_a_flag_merged_before_the_engines_settles_a_candidate_engines_flag_without_a_sweep_object():
    """Integration (batch 905, with B-132): the flags in rep.flags before the engine loop are the sweep's.
    A report seeded that way (B-132's disputed-flag tests build it so) confirms like a sweep object does;
    the candidate engine's own flag, merged in the loop, never confirms itself."""
    prof = profile()
    rep = I.Report("9167", None, SolverResult("none"))
    rep.flags[FLAG] = ["sweep plain in cert.pem"]
    rep.runs = [_run("toolkits.series_chain", "candidate")]
    I._merge(rep, prof, "")
    res = I._result(rep, "9167")
    assert res.status == "solved" and rep.unconfirmed == {}
    rep, _ = _intake([_run("toolkits.series_chain", "candidate")])            # nothing merged before
    assert rep.result.status == "candidate" and FLAG in rep.unconfirmed
