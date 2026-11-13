"""B-196: the integrity checks hold on this tree. The gate selects this file for any change to a source
or test file (tests/gate.toml [[scan]]), so a new fake branch without a non-fake test, an uncollected test
file, or a known solve path whose test was renamed or hollowed fails here."""
from __future__ import annotations

from ctf import paths
from ctf.integrity import collected, fakes, preserve

ROOT = paths.repo_root()


def test_every_fake_branch_has_a_non_fake_test():
    res = fakes.audit(ROOT)
    assert res.findings == []
    # the branches B-196 found without one when it shipped, now each reached with the flag off
    keys = {b.key for b in res.branches if b.status == "COVERED"}
    assert {"ctf/doctor.py::check_token", "ctf/toolbox.py::apply", "ctf/toolchain/images.py::docker_path",
            "solvers/binary/evidence.py::hidden", "solvers/common/labels.py::_mask",
            "solvers/script-analysis/plan_codec.py::hidden"} <= keys


def test_every_test_file_is_collected_and_gated():
    res = collected.audit(ROOT)
    assert res.new == [] and res.stale == []


def test_known_solve_paths_keep_live_tests():
    res = preserve.check(ROOT)
    assert {s.id for s in res.solves} >= {"jwt-alg-none", "jws-rfc7797-b64-false"}
    assert res.findings == []
