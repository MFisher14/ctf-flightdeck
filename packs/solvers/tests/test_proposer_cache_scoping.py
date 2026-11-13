#!/usr/bin/env python3
"""Non-fake cache scoping for the offline proposer evidence/runtime path."""
from __future__ import annotations

import base64
import hashlib
import sys
import threading
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))

import proposer_model as pm  # noqa: E402


def main():
    encoded = base64.b64encode(b"ANS-0123456789ABCDEF")
    pm._EV_CACHE.clear()

    short = pm.evidence("answer.txt", encoded, time.time() - 1.0)
    assert short["decoded"] == [], short["decoded"]

    # Do not clear the cache: the expired extraction must not poison a later call with enough time.
    rich = pm.evidence("answer.txt", encoded, time.time() + 1.0)
    assert any(x.get("text") == "ANS-0123456789ABCDEF" for x in rich["decoded"]), rich["decoded"]

    q1 = {"qid": "same", "question": "Decode the first value", "answer_format": {"kind": "text"}}
    q2 = {"qid": "same", "question": "Decode the second value", "answer_format": {"kind": "text"}}
    assert pm._question_scope(q1) != pm._question_scope(q2)

    keys = list(pm._EV_CACHE)
    assert len(keys) == 1 and keys[0][0] == hashlib.sha256(encoded).digest(), keys

    # The sibling look-ahead cache is process-warm in the real proposer
    # service.  One attempt must not globally latch it off for every later
    # attempt, and speculative work may not create an unbounded queue of
    # daemon threads behind its semaphore.
    q = {"qid": "code", "question": "Read the code", "answer_format": {"kind": "text"}}
    todo = [{"qid": "code", "q": q}]
    old_model, old_evidence, old_local, old_ahead = (pm._model_chunk, pm.evidence,
                                                      pm.pe.local_candidates, pm._AHEAD)
    lock = threading.Lock()
    state = {"active": 0, "maximum": 0, "calls": 0}

    def model(units, _deadline):
        with lock:
            state["active"] += 1
            state["maximum"] = max(state["maximum"], state["active"])
            state["calls"] += 1
        time.sleep(0.03)
        try:
            return {u["qid"]: [("model", u["names"][0])] for u in units}
        finally:
            with lock:
                state["active"] -= 1

    def ev(name, raw, _deadline):
        return {"name": name, "size": len(raw), "text": raw.decode("ascii")}

    try:
        pm._model_chunk, pm.evidence = model, ev
        pm.pe.local_candidates = lambda _q, _evs: []
        pm._AHEAD = threading.BoundedSemaphore(1)
        pm._SIB.clear()

        def run_pair(a, b):
            da = hashlib.sha256(a).hexdigest()
            db = hashlib.sha256(b).hexdigest()
            pm._prefetch_siblings([q], {"siblings": {"0": a, "1": b}}, todo, da)
            key = (db, "code", pm._question_scope(q))
            end = time.time() + 1.0
            while key not in pm._SIB and time.time() < end:
                time.sleep(0.005)
            assert key in pm._SIB, (key, pm._SIB)

        run_pair(b"attempt-one-current", b"attempt-one-next")
        run_pair(b"attempt-two-current", b"attempt-two-next")
        assert len([k for k in pm._SIB if k[0] == "__started__"]) == 2, pm._SIB

        # While one admitted worker is slow, calls from distinct deliveries
        # are refused without leaving waiting threads or permanent markers.
        pm._SIB.clear()
        for i in range(12):
            a, b = f"current-{i}".encode(), f"next-{i}".encode()
            pm._prefetch_siblings([q], {"siblings": {"0": a, "1": b}}, todo,
                                  hashlib.sha256(a).hexdigest())
        end = time.time() + 1.0
        while state["active"] and time.time() < end:
            time.sleep(0.005)
        assert state["maximum"] == 1, state
        assert len([k for k in pm._SIB if k[0] == "__started__"]) <= 1, pm._SIB
        with pm._SIB_LOCK:
            for i in range(pm._SIB_MAX + 10):
                pm._sib_put_locked(("delivery", str(i), b"scope"), [])
            assert len(pm._SIB) == pm._SIB_MAX
    finally:
        pm._model_chunk, pm.evidence, pm.pe.local_candidates, pm._AHEAD = (old_model, old_evidence,
                                                                          old_local, old_ahead)
        pm._SIB.clear()

    print("PASS: proposer cache scopes content/deadlines/questions and bounds per-delivery sibling prefetch/cache (9/9)")
    return 0


def test_proposer_cache_scoping():
    """pytest entry: main() asserts every scoping check and returns 0 only when all pass."""
    assert main() == 0


if __name__ == "__main__":
    raise SystemExit(main())
