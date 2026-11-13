#!/usr/bin/env python3
"""Offline regression for untrusted web-candidate terminal/evidence output.

No socket is opened. Target values may remain intact in structured JSON, whose
encoder escapes controls, but every human-facing evidence/stderr seam must
remove C0/ESC/BEL, DEL, and C1 controls before display.
"""

import contextlib
import io
import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
WEB = REPO / "solvers" / "web"
TOOLKITS = REPO / "solvers" / "toolkits"
for folder in (str(TOOLKITS), str(WEB)):
    if folder not in sys.path:
        sys.path.insert(0, folder)

import web as TK  # noqa: E402
import forge_event as FE  # noqa: E402
import passive_checks as PASSIVE  # noqa: E402
import post_chain as POST  # noqa: E402
import proof_hunt as PH  # noqa: E402
import reset_rebind as RESET  # noqa: E402


EVIL = "\x1b]52;c;SGVsbG8=\x07flag{candidate}\nrewritten\x7f\x9b31m"


def clean(value):
    return not any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)


def assert_lines(label, lines):
    assert lines, f"{label}: no surfaced line"
    assert all(clean(line) for line in lines), f"{label}: control reached display: {lines!r}"
    assert all(len(line) <= 600 for line in lines), f"{label}: unbounded display: {lines!r}"
    assert any("flag{candidate}" in line for line in lines), f"{label}: useful candidate was lost"


def test_shared_helper_and_json_boundary():
    shown = TK.safe_display_text(EVIL, 40)
    assert clean(shown) and len(shown) <= 40 and "flag{candidate}" in shown
    encoded = json.dumps({"candidate": EVIL})
    assert clean(encoded), encoded
    assert json.loads(encoded)["candidate"] == EVIL  # persistence preserves data, escaped on disk


def test_peer_evidence_seams():
    ctx = {"evidence": []}
    FE._append_evidence(ctx, f"WEB FORGE CANDIDATE proof-1: {EVIL}")
    assert_lines("forge", ctx["evidence"])

    ctx = {"evidence": []}
    POST._append_evidence(ctx, f"WEB POST-CHAIN CANDIDATE proof-1: {EVIL}")
    assert_lines("post-chain", ctx["evidence"])

    ctx = {"evidence": []}
    RESET._surface(ctx, "proof-1", [EVIL])
    assert_lines("reset", ctx["evidence"])

    class Checks:
        @staticmethod
        def result():
            return {
                "findings": [{"class": EVIL, "confirmed": True, "evidence": EVIL, "path": EVIL}],
                "candidates": [EVIL],
            }

    ctx = {"evidence": []}
    PASSIVE._publish(Checks(), {"answer_id": "proof-1"}, ctx)
    assert_lines("passive", ctx["evidence"])


def test_proof_hunt_evidence_and_stderr():
    original = PH._Hunter

    class CandidateHunter:
        def __init__(self, *_args, **_kwargs):
            self.candidates = [{"value": EVIL, "path": "/payoff", "shape": "test"}]

        def run(self):
            return None

        def stop_now(self):
            return None

    evidence = []
    stderr = io.StringIO()
    PH._Hunter = CandidateHunter
    try:
        with contextlib.redirect_stderr(stderr):
            result = PH.solve_targets(
                [{"answer_id": "proof-1", "url": "http://target.test/", "question": ""}],
                {"max_requests": 0, "evidence": evidence},
            )
    finally:
        PH._Hunter = original
    assert result == {"proof-1": None}, result
    assert_lines("proof-hunt evidence", evidence)
    terminal_lines = [line for line in stderr.getvalue().splitlines() if line]
    assert_lines("proof-hunt stderr", terminal_lines)


def main():
    test_shared_helper_and_json_boundary()
    test_peer_evidence_seams()
    test_proof_hunt_evidence_and_stderr()
    print("RESULT PASS (web display safety)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
