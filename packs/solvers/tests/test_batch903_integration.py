"""Batch-903 integration fixes: routes that only collided once the items met on one tree.

* B-110 (`toolkits.cipher_invert`) claimed the bare keywords `s-box` / `sbox` at priority 63, above
  `common.crypto_faults`' white-box AES / fault-signature wording (60), so a white-box AES brief routed to
  the custom-cipher inverter first (tests/test_round5_crypto_faults_ecdh.py). Its keyword route is now 59:
  still first for home-built cipher wording, second to crypto_faults for white-box and fault wording.
* B-124 (`web.invariant_harness`) shipped with no [[routes]], which the manifest lint refuses
  (tests/test_engines_lint.py, `no-route`). It now routes on business-logic / invariant wording, above the
  agent-handoff playbook that also lists `business logic` (priority 20).

The checks read the real route table through ctf.triage, offline.
"""
from ctf import triage


def _first(category: str, text: str) -> str:
    return triage.suggest(category, text)["engines"][0]


def test_white_box_aes_wording_routes_crypto_faults_before_the_cipher_inverter():
    engines = triage.suggest("crypto", "a white-box AES with its S-box tables")["engines"]
    assert engines[0] == "solvers/common/crypto_faults.py"
    assert "solvers/toolkits/cipher_invert.py" in engines


def test_home_built_cipher_wording_still_routes_the_cipher_inverter_first():
    assert _first("crypto", "a home-built cipher with an s-box; run it backward") == "solvers/toolkits/cipher_invert.py"
    assert _first("misc", "a homebrew cipher sbox") == "solvers/toolkits/cipher_invert.py"


def test_business_logic_wording_routes_the_invariant_harness():
    assert _first("web", "business logic: the coupon applies twice and a state invariant breaks") == \
        "solvers/web/invariant_harness.py"
    route = triage.suggest("web", "an invariant spec for the cart")
    assert any(r["id"] == "web.invariant_harness" for r in route["routes"])


def test_the_invariant_harness_is_not_offered_outside_web():
    assert "solvers/web/invariant_harness.py" not in triage.suggest("crypto", "business logic")["engines"]


def test_the_b253_lane_solver_reads_its_own_day_module_when_another_is_cached(tmp_path, monkeypatch):
    """B-253's fixture lane solver imported its day modules flatly (`d30`), so in a test process where an
    earlier test had imported solvers/binary/d30.py the serial in-process replay used that module and
    answered nothing (tests/test_b253_gate_replay.py failed in both full runs of batch 903, alone it passed).
    A module of that name from another folder must not be used."""
    import sys
    import types

    import adapt_repo as AR
    import b253_fixtures as F
    from ctf.adapt import replay as P

    root = AR.make_repo(tmp_path)
    solver = F.write_lane(root)
    folder = F.save_attempt(tmp_path / "rows" / "binary-day-30-mastery",
                            {1: ("d30--one.txt", b"gamma\n", ["d30_word"]), 2: ("d30--two.txt", b"delta\n", ["d30_word"])})
    foreign = types.ModuleType("d30")
    foreign.__file__ = str(tmp_path / "elsewhere" / "d30.py")
    monkeypatch.setitem(sys.modules, "d30", foreign)
    run = P.replay_attempt(folder, solver, pooled=False)
    assert run.answers == {"set1.d30_word": F.day_answer("thirty", "d30_word", b"gamma\n"),
                           "set2.d30_word": F.day_answer("thirty", "d30_word", b"delta\n")}
