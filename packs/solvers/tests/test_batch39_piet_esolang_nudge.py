"""Batch-39 integration fix (B-055 x triage): the Piet route must not claim the
bare generic keyword "esolang".

B-055 gave common.piet a keyword route at priority 62 that included the generic
token "esolang". That token outranked the esolang_tail "fractran" nudge (priority
60), so a brief like "A FRACTRAN esolang program" was fronted by solvers/common/piet.py
instead of the FRACTRAN-specific engine. The fix drops "esolang" from the Piet route,
keeping only Piet-specific tokens. This test fails if that generic token comes back.

Offline, no network, no challenge binaries.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import triage  # noqa: E402


def test_generic_esolang_brief_does_not_front_piet():
    # A FRACTRAN program names a specific esolang, not Piet.
    engines = triage.suggest("misc", "A FRACTRAN esolang program")["engines"]
    assert engines[0] == "solvers/warmups/esolang_tail.py"
    assert engines[0] != "solvers/common/piet.py"


def test_a_bare_esolang_mention_does_not_front_piet():
    # The word "esolang" alone, with no Piet/codel cue, must not pull in Piet.
    engines = triage.suggest("misc", "some unknown esolang challenge")["engines"]
    assert engines[0] != "solvers/common/piet.py"


def test_a_piet_brief_still_routes_to_piet():
    # The fix preserves B-055's intent: a Piet/codel brief still ranks Piet.
    out = triage.suggest("rev", "a piet codel image program")
    ids = [r["id"] for r in out["routes"]]
    assert "common.piet" in ids
