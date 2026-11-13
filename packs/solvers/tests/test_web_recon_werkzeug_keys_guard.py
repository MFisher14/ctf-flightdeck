#!/usr/bin/env python3
"""Merge-specific checks for the Werkzeug PIN peer's contract.

The hand-merge of ``recon_werkzeug.py`` (batch hm-09) kept the CSCTF
rebrand but had to (a) accept *both* the CSCTF ``flag_file_path`` and the
Huntress ``objective_path`` contract key, and (b) keep the file-path guard
deliberate against ``..`` traversal even though CSCTF widened the regex from
the ``/run/huntress/`` prefix to any absolute path.  The repo's main
loopback test (``test_web_recon_werkzeug.py``) exercises ``objective_path``
and the ``/../`` substring case only; these direct-unit checks cover the two
behaviours that merge added.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

import recon_werkzeug as reader  # noqa: E402

BASE_URL = "http://target.local"

# A fully valid contract minus the file-path key; the PIN inputs below derive a
# real 3-3-3 PIN, so ``_contract`` returns a dict only when every gate passes.
_GOOD = {
    "contract": "werkzeug_debug_pin", "console_route": "/console",
    "debugger_secret": "fixture-debugger-secret-47", "werkzeug_version": "3.1.3",
    "pin_algorithm": "sha1", "username": "web3_user", "modname": "flask.app",
    "appname": "Flask", "appfile": "/usr/local/lib/python3.5/dist-packages/flask/app.py",
    "mac": 279275995014060, "machine_id": "d4e6cb65d59544f3331ea0425dc555a1",
    "frame": 0,
}


def _row(**changes):
    row = copy.deepcopy(_GOOD)
    row.update(changes)
    return row


def test_contract_accepts_both_file_path_keys():
    csctf = reader._contract(_row(flag_file_path="/run/csctf/flag.txt"), BASE_URL)
    huntress = reader._contract(_row(objective_path="/run/huntress/objective.txt"), BASE_URL)
    assert csctf is not None and csctf["flag_file"] == "/run/csctf/flag.txt", csctf
    assert huntress is not None and huntress["flag_file"] == "/run/huntress/objective.txt", huntress


def test_contract_prefers_flag_file_path_when_both_present():
    both = reader._contract(
        _row(flag_file_path="/run/csctf/flag.txt",
             objective_path="/run/huntress/objective.txt"),
        BASE_URL)
    assert both is not None and both["flag_file"] == "/run/csctf/flag.txt", both


def test_contract_rejects_row_with_no_file_path_key():
    assert reader._contract(_row(), BASE_URL) is None


def test_guard_rejects_dotdot_segments_including_bare_and_trailing():
    # CSCTF's widened regex matches all of these; the deliberate guard must not.
    for bad in ("/run/..", "/..", "/run/huntress/../secret", "/a/../b",
                "/run/../etc/passwd", "/etc/passwd/.."):
        assert reader._safe_flag_file(bad) is None, bad
        assert reader._contract(_row(flag_file_path=bad), BASE_URL) is None, bad


def test_guard_still_accepts_plain_absolute_paths_outside_run_huntress():
    # The widening itself (any absolute path, not just /run/huntress/) is kept.
    for ok in ("/run/csctf/flag.txt", "/srv/app/flag", "/etc/app/flag.conf",
               "/opt/ctf/the_flag"):
        assert reader._safe_flag_file(ok) == ok, ok
