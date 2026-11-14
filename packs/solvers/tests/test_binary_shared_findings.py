"""B-165: the shared findings board and its pinned acceptance gate (tools/shared_findings.py).

The gate must re-verify a real proof (a hashlib preimage, a reimplemented validator, a format regex)
and refuse an unproven guess; the gate is pinned to the board, so a racer cannot swap in a looser one,
and every read re-runs it, so a forged or stale accepted row is flagged, never listed. Appends hold an
exclusive lock (proven across processes); a corrupt log or gate file fails loud.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

import shared_findings as sf
from ctf import event, flagfmt, ledger

SF_PATH = Path(sf.__file__).resolve()


def _board(tmp_path, gate=None, **kw):
    return sf.FindingsBoard(tmp_path / "findings.jsonl", gate=gate, **kw)


def _raw_append(path, **row):
    base = {"schema": 1, "ts": 1.0, "agent": "forger", "summary": "", "evidence": [], "proof": None,
            "candidate": None, "kind": "note", "status": "open"}
    base.update(row)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(base) + "\n")


# ------------------------------------------------------------------------------- record / latest

def test_record_appends_and_latest_reduces_by_key(tmp_path):
    board = _board(tmp_path)
    board.record(sf.Finding(key="op-0x1a", agent="a1", summary="first guess", kind="hypothesis"))
    board.record(sf.Finding(key="op-0x1a", agent="a2", summary="refined", kind="note",
                            evidence=["handler xors [rsp] with imm8"]))
    board.record(sf.Finding(key="stage2", agent="a1", summary="decrypt loop", kind="note"))
    assert len(board.entries()) == 3
    latest = board.latest()
    assert set(latest) == {"op-0x1a", "stage2"}
    assert latest["op-0x1a"].summary == "refined"          # last write wins
    assert latest["op-0x1a"].evidence == ("handler xors [rsp] with imm8",)


def test_record_after_accept_does_not_hide_the_flag(tmp_path):
    # the verification probe: accept under key "flag", then another racer records under "flag"
    want = hashlib.sha1(b"FLAG{real}").hexdigest()
    board = _board(tmp_path, gate=sf.digest_gate("sha1", want))
    board.accept(sf.Finding(key="flag", agent="a5", summary="preimage", candidate="FLAG{real}"))
    other = sf.FindingsBoard(board.path)                   # a second racer, no gate of its own
    other.record(sf.Finding(key="flag", agent="a7", summary="my guess", kind="candidate",
                            candidate="FLAG{guess}"))
    assert [f.candidate for f in other.accepted()] == ["FLAG{real}"]
    assert [f.candidate for f in board.accepted()] == ["FLAG{real}"]
    assert other.latest()["flag"].status == "accepted"      # an open row never replaces an accepted one
    assert other.latest()["flag"].candidate == "FLAG{real}"


# ----------------------------------------------------------------------------------- the gates

def test_digest_gate_accepts_preimage_and_rejects_wrong(tmp_path):
    want = hashlib.sha1(b"CTF{the_preimage}").hexdigest()
    board = _board(tmp_path, gate=sf.digest_gate("sha1", want.upper()))   # hex case is normalised
    with pytest.raises(sf.AcceptanceRejected, match="failed the acceptance gate"):
        board.accept(sf.Finding(key="flag", agent="a9", summary="guess", candidate="CTF{nope}"))
    assert board.entries() == []                            # nothing written on a rejection

    acc = board.accept(sf.Finding(key="flag", agent="a9", summary="preimage",
                                  candidate="CTF{the_preimage}", proof={"note": "from the stored digest"}))
    assert acc.status == "accepted" and acc.kind == "accepted"
    # the accepted row carries the pinned gate it passed, so a reader can replay it
    assert acc.proof == {"note": "from the stored digest",
                         "gate": {"gate": "digest", "algo": "sha1", "expected": want, "encoding": "utf-8"}}
    assert [f.candidate for f in board.accepted()] == ["CTF{the_preimage}"]


def test_predicate_gate_runs_the_validator(tmp_path):
    def reversed_is_tset(b):
        return b[::-1] == b"tset"

    board = _board(tmp_path, gate=sf.predicate_gate(reversed_is_tset))
    with pytest.raises(sf.AcceptanceRejected):
        board.accept(sf.Finding(key="k", agent="a", summary="wrong", candidate="nope"))
    assert board.accept(sf.Finding(key="k", agent="a", summary="ok", candidate="test")).status == "accepted"
    assert [f.candidate for f in board.accepted()] == ["test"]


def test_predicate_gate_lambda_needs_a_name():
    with pytest.raises(sf.FindingsError, match="name"):
        sf.predicate_gate(lambda b: True)
    spec = sf.predicate_gate(lambda b: True, name="v1").to_dict()
    assert spec == {"gate": "predicate", "name": "v1", "code": sf.code_digest(lambda b: True)}
    assert len(spec["code"]) == 64


def _make_eq(secret):
    return lambda b: b == secret


def test_code_digest_tracks_what_the_predicate_does():
    # the same source written again gives the same digest (an honest second reader re-verifies)
    assert sf.code_digest(lambda b: b == b"good") == sf.code_digest(lambda b: b == b"good")
    # different bytecode, constants, closure values or defaults give a different digest
    assert sf.code_digest(lambda b: True) != sf.code_digest(lambda b: False)
    assert sf.code_digest(lambda b: b == b"good") != sf.code_digest(lambda b: b == b"evil")
    assert sf.code_digest(_make_eq(b"x")) != sf.code_digest(_make_eq(b"y"))
    assert sf.code_digest(_make_eq(b"x")) == sf.code_digest(_make_eq(b"x"))

    def with_default(b, k=1):
        return len(b) == k

    def with_other_default(b, k=2):
        return len(b) == k

    assert sf.code_digest(with_default) != sf.code_digest(with_other_default)
    # a closed-over helper function is digested too
    def helper_a(b):
        return b.upper()

    def helper_b(b):
        return b.lower()

    def outer(helper):
        return lambda b: helper(b) == b"OK"

    assert sf.code_digest(outer(helper_a)) != sf.code_digest(outer(helper_b))


def test_code_digest_refuses_what_it_cannot_pin():
    class Validator:
        def __call__(self, b):
            return True

    with pytest.raises(sf.FindingsError, match="plain Python function"):
        sf.predicate_gate(Validator(), name="obj")
    opaque = object()
    with pytest.raises(sf.FindingsError, match="closure value of type object"):
        sf.predicate_gate(lambda b: opaque is not None, name="opaque")


def test_a_predicate_spoofed_under_the_pinned_name_is_refused(tmp_path):
    # the verification probe: predicate_gate(lambda b: True, name=<the pinned name>) must not pass
    board = _board(tmp_path, gate=sf.predicate_gate(lambda b: b == b"good", name="validator-v1"))
    with pytest.raises(sf.FindingsError, match="pinned to gate"):
        sf.FindingsBoard(board.path, gate=sf.predicate_gate(lambda b: True, name="validator-v1"))
    # nothing was accepted, and a reader with the real predicate sees no rows
    real = sf.FindingsBoard(board.path, gate=sf.predicate_gate(lambda b: b == b"good", name="validator-v1"))
    assert real.accepted() == [] and real.flagged() == []
    # a pin by name alone (hand-written gate file) is refused as spoofable
    with pytest.raises(sf.FindingsError, match="code' digest"):
        sf.GateSpec.from_dict({"gate": "predicate", "name": "validator-v1"})
    # a callable whose digest differs from a given one is refused
    pinned = sf.predicate_gate(lambda b: b == b"good", name="validator-v1").to_dict()
    with pytest.raises(sf.FindingsError, match="does not match"):
        sf.GateSpec("predicate", {k: v for k, v in pinned.items() if k != "gate"}, lambda b: True)


def test_predicate_rows_are_unverifiable_without_the_predicate(tmp_path):
    check = sf.predicate_gate(lambda b: b == b"good", name="validator-v1")
    board = _board(tmp_path, gate=check)
    board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="good"))
    reader = sf.FindingsBoard(board.path)                   # no predicate supplied
    assert reader.accepted() == []
    [v] = reader.flagged()
    assert "unverifiable" in v.reason and "validator-v1" in v.reason
    with pytest.raises(sf.FindingsError, match="predicate_gate"):
        reader.accept(sf.Finding(key="flag", agent="b", summary="x", candidate="good"))
    # a reader that brings the same predicate re-verifies the row
    again = sf.FindingsBoard(board.path, gate=sf.predicate_gate(lambda b: b == b"good", name="validator-v1"))
    assert [f.candidate for f in again.accepted()] == ["good"]


def test_regex_gate_needs_a_full_match(tmp_path):
    rx = _board(tmp_path, gate=sf.regex_gate(r"tok-[a-z_]+"))
    with pytest.raises(sf.AcceptanceRejected):
        rx.accept(sf.Finding(key="k", agent="a", summary="bad format", candidate="tok-NOPE!"))
    with pytest.raises(sf.AcceptanceRejected):                # a partial match is not a match
        rx.accept(sf.Finding(key="k", agent="a", summary="embedded", candidate="xxtok-good"))
    with pytest.raises(sf.AcceptanceRejected):
        rx.accept(sf.Finding(key="k", agent="a", summary="prefix only", candidate="tok-good-trailing"))
    assert rx.accept(sf.Finding(key="k", agent="a", summary="ok", candidate="tok-good")).status == "accepted"


def test_flagfmt_gate_uses_the_event_format(tmp_path):
    ff = flagfmt.for_profile(event.load("csctf"))           # prefixes CSCTF/chronos/CTF/flag, prefix-insensitive
    board = _board(tmp_path, gate=sf.flagfmt_gate(ff))
    with pytest.raises(sf.AcceptanceRejected):
        board.accept(sf.Finding(key="flag", agent="a", summary="wrong prefix", candidate="HTB{x}"))
    assert board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="csctf{abc}")).status == "accepted"
    # the pinned spec is the compiled event regex, re-verified by a reader without the event
    pinned = json.loads(sf.gate_path(board.path).read_text())
    assert pinned["gate"] == "regex" and pinned["pattern"] == ff.regex.pattern
    assert [f.candidate for f in sf.FindingsBoard(board.path).accepted()] == ["csctf{abc}"]


def test_flagfmt_gate_pins_ignorecase_for_an_insensitive_event(tmp_path):
    # a synthetic case="insensitive" event format: the whole match ignores case
    spec = replace(event.load("csctf").flag, case="insensitive")
    ff = flagfmt.FlagFormat(spec)
    assert ff.regex.flags & re.IGNORECASE
    gate = sf.flagfmt_gate(ff)
    assert gate.to_dict()["ignorecase"] is True
    board = _board(tmp_path, gate=gate)
    pinned = json.loads(sf.gate_path(board.path).read_text())
    assert pinned["ignorecase"] is True
    # a swapped-case flag is accepted (the exact-case pattern alone would reject it) ...
    swapped = "cScTf{AbC}"
    assert ff.is_flag(swapped)
    assert re.fullmatch(ff.regex.pattern, swapped) is None
    assert board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate=swapped)).status == "accepted"
    # ... and re-verifies for a reader with only the pinned gate
    assert [f.candidate for f in sf.FindingsBoard(board.path).accepted()] == [swapped]
    with pytest.raises(sf.AcceptanceRejected):
        board.accept(sf.Finding(key="flag", agent="a", summary="wrong prefix", candidate="htb{abc}"))
    # an exact-case event pins ignorecase False
    exact = flagfmt.FlagFormat(replace(spec, case="exact"))
    assert sf.flagfmt_gate(exact).to_dict()["ignorecase"] is False


def test_accept_requires_a_pinned_gate_and_a_candidate(tmp_path):
    with pytest.raises(sf.FindingsError, match="no pinned acceptance gate"):
        _board(tmp_path).accept(sf.Finding(key="k", agent="a", summary="x", candidate="y"))
    board = _board(tmp_path / "g", gate=sf.digest_gate("md5", "0" * 32))
    with pytest.raises(sf.AcceptanceRejected, match="no candidate"):
        board.accept(sf.Finding(key="k", agent="a", summary="no candidate"))


def test_record_refuses_to_mark_accepted(tmp_path):
    board = _board(tmp_path)
    with pytest.raises(sf.FindingsError, match="use accept"):
        board.record(sf.Finding(key="flag", agent="a", summary="cheating", candidate="x",
                                kind="accepted"))
    with pytest.raises(sf.FindingsError, match="use accept"):
        board.record(sf.Finding(key="flag", agent="a", summary="cheating", candidate="x",
                                status="accepted"))


def test_bad_gate_specs_are_named():
    with pytest.raises(sf.FindingsError, match="unknown digest algorithm"):
        sf.digest_gate("not-a-hash", "00")
    with pytest.raises(sf.FindingsError, match="hex digest"):
        sf.digest_gate("sha1", "not hex")
    with pytest.raises(sf.FindingsError, match="does not compile"):
        sf.regex_gate("(")
    with pytest.raises(sf.FindingsError, match="gate kind"):
        sf.GateSpec("vibes", {})


# ------------------------------------------------------------------------------ the pinned gate

def test_gate_is_pinned_and_a_different_gate_is_refused(tmp_path):
    want = hashlib.sha256(b"FLAG{x}").hexdigest()
    board = _board(tmp_path, gate=sf.digest_gate("sha256", want))
    assert json.loads(sf.gate_path(board.path).read_text()) == {
        "gate": "digest", "algo": "sha256", "expected": want, "encoding": "utf-8"}
    assert sf.gate_path(board.path).name == "findings.gate.json"
    # the same gate again is fine; a looser one is refused (the probe: a racer's always-true gate)
    sf.FindingsBoard(board.path, gate=sf.digest_gate("sha256", want))
    with pytest.raises(sf.FindingsError, match="pinned to gate"):
        sf.FindingsBoard(board.path, gate=sf.regex_gate("FLAG.+"))
    with pytest.raises(sf.FindingsError, match="GateSpec"):
        sf.FindingsBoard(board.path, gate=lambda f: True)
    # a racer with no gate of its own still runs the pinned one on accept
    other = sf.FindingsBoard(board.path)
    with pytest.raises(sf.AcceptanceRejected):
        other.accept(sf.Finding(key="flag", agent="b", summary="guess", candidate="FLAG{guess}"))
    assert other.accept(sf.Finding(key="flag", agent="b", summary="ok", candidate="FLAG{x}")).status == "accepted"


def test_hand_forged_accepted_row_is_flagged_not_listed(tmp_path):
    board = _board(tmp_path, gate=sf.regex_gate(r"tok-[a-z]+"))
    _raw_append(board.path, key="flag", kind="accepted", status="accepted", candidate="tok-FORGED-1")
    assert board.accepted() == []
    [v] = board.flagged()
    assert v.finding.candidate == "tok-FORGED-1" and "fails the pinned gate" in v.reason
    # a later honest accept is listed; the forged row stays flagged
    board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="tok-real"))
    assert [f.candidate for f in board.accepted()] == ["tok-real"]
    assert [v.finding.candidate for v in board.flagged()] == ["tok-FORGED-1"]


def test_accepted_rows_on_an_ungated_board_are_unverifiable(tmp_path):
    board = _board(tmp_path)
    _raw_append(board.path, key="flag", kind="accepted", status="accepted", candidate="FLAG{x}")
    assert board.accepted() == []
    [v] = board.audit()
    assert not v.ok and "no pinned gate" in v.reason


def test_inconsistent_kind_and_status_row_is_rejected(tmp_path):
    board = _board(tmp_path)
    _raw_append(board.path, key="flag", kind="note", status="accepted", candidate="FLAG{x}")
    with pytest.raises(sf.FindingsError, match="inconsistent row"):
        board.entries()
    other = _board(tmp_path / "b")
    _raw_append(other.path, key="flag", kind="accepted", status="open", candidate="FLAG{x}")
    with pytest.raises(sf.FindingsError, match="inconsistent row"):
        other.entries()


@pytest.mark.parametrize("pattern", ["", ".*", "x*", "(?:)", r"[\s\S]*"])
def test_a_regex_gate_matching_the_empty_string_is_refused(pattern):
    with pytest.raises(sf.FindingsError, match="empty string"):
        sf.regex_gate(pattern)


@pytest.mark.parametrize("pattern", [".+", r"[\s\S]+", r"[^\n]+", r"\S.*"])
def test_a_regex_gate_matching_arbitrary_text_is_refused(pattern):
    with pytest.raises(sf.FindingsError, match="arbitrary unrelated text"):
        sf.regex_gate(pattern)


def test_a_loose_regex_is_refused_from_a_hand_written_gate_file_too(tmp_path):
    board = _board(tmp_path)
    sf.gate_path(board.path).write_text(json.dumps({"gate": "regex", "pattern": ".+"}))
    with pytest.raises(sf.FindingsError, match="arbitrary unrelated text"):
        board.accept(sf.Finding(key="flag", agent="a", summary="junk", candidate="junk"))
    assert board.entries() == []
    # a constraining pattern that still matches some probes is fine
    assert sf.regex_gate(r"[a-z]+").to_dict()["pattern"] == "[a-z]+"


def _log_rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def test_pinning_writes_a_gate_pin_anchor_as_the_first_log_line(tmp_path):
    gate = sf.regex_gate(r"tok-[a-z]+")
    board = _board(tmp_path, gate=gate)
    rows = _log_rows(board.path)
    assert len(rows) == 1 and rows[0]["gate_pin"] == gate.to_dict() and rows[0]["schema"] == 1
    assert board.anchored_gate().same_as(gate)
    # re-opening with the same gate adds no second anchor; the anchor is not a finding
    sf.FindingsBoard(board.path, gate=gate)
    board.record(sf.Finding(key="k", agent="a", summary="x"))
    assert [("gate_pin" in r) for r in _log_rows(board.path)] == [True, False]
    assert [e.key for e in board.entries()] == ["k"]


def test_a_board_pinned_after_records_still_gets_an_anchor(tmp_path):
    board = _board(tmp_path)
    board.record(sf.Finding(key="early", agent="a", summary="before any gate"))
    gate = sf.regex_gate(r"tok-[a-z]+")
    sf.FindingsBoard(board.path, gate=gate)
    rows = _log_rows(board.path)
    assert "gate_pin" not in rows[0] and rows[1]["gate_pin"] == gate.to_dict()
    assert board.anchored_gate().same_as(gate)


def test_deleting_the_gate_file_does_not_unpin_the_board(tmp_path):
    # the verification probe: delete findings.gate.json, re-pin a looser gate, accept junk
    gate = sf.regex_gate(r"tok-[a-z]+")
    board = _board(tmp_path, gate=gate)
    sf.gate_path(board.path).unlink()
    with pytest.raises(sf.FindingsError, match="pinned to gate"):
        sf.FindingsBoard(board.path, gate=sf.regex_gate(r"[a-z]+"))
    assert not sf.gate_path(board.path).exists()
    reader = sf.FindingsBoard(board.path)
    assert reader.pinned_gate().same_as(gate)               # the anchor still holds
    with pytest.raises(sf.AcceptanceRejected):
        reader.accept(sf.Finding(key="flag", agent="b", summary="junk", candidate="junk"))
    # an honest racer re-opening with the same gate restores the gate file
    sf.FindingsBoard(board.path, gate=gate)
    assert json.loads(sf.gate_path(board.path).read_text()) == gate.to_dict()


def test_a_gate_file_changed_after_pinning_flags_the_board(tmp_path):
    gate = sf.regex_gate(r"tok-[a-z]+")
    board = _board(tmp_path, gate=gate)
    board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="tok-real"))
    sf.gate_path(board.path).write_text(json.dumps(sf.regex_gate(r"[a-z]+").to_dict()))
    reader = sf.FindingsBoard(board.path)
    with pytest.raises(sf.GateTampered, match="changed after pinning"):
        reader.pinned_gate()
    with pytest.raises(sf.GateTampered):
        reader.accept(sf.Finding(key="flag", agent="b", summary="junk", candidate="junk"))
    assert reader.accepted() == []                          # even the honest row is not listed now
    [v] = reader.flagged()
    assert v.finding.candidate == "tok-real" and "changed after pinning" in v.reason
    with pytest.raises(sf.FindingsError, match="pinned to gate|changed after pinning"):
        sf.FindingsBoard(board.path, gate=sf.regex_gate(r"[a-z]+"))
    assert all(e.candidate != "junk" for e in reader.entries())


def test_only_the_first_gate_pin_row_is_the_anchor(tmp_path):
    gate = sf.regex_gate(r"tok-[a-z]+")
    board = _board(tmp_path, gate=gate)
    with open(board.path, "a", encoding="utf-8") as fh:     # a forged later anchor for a looser gate
        fh.write(json.dumps({"schema": 1, "ts": 2.0, "gate_pin": sf.regex_gate(r"[a-z]+").to_dict()}) + "\n")
    assert board.anchored_gate().same_as(gate)
    assert board.pinned_gate().same_as(gate)


def test_corrupt_gate_file_fails_loudly(tmp_path):
    board = _board(tmp_path)
    sf.gate_path(board.path).write_text("{not json")
    with pytest.raises(sf.FindingsError, match="not JSON"):
        board.pinned_gate()
    sf.gate_path(board.path).write_text(json.dumps({"algo": "sha1"}))
    with pytest.raises(sf.FindingsError, match="'gate' field"):
        board.pinned_gate()


# --------------------------------------------------------------------------- files, lock, ledger

def test_board_and_gate_files_are_owner_only(tmp_path):
    board = _board(tmp_path, gate=sf.regex_gate(r"F\{.*\}"))
    board.record(sf.Finding(key="k", agent="a", summary="x"))
    assert stat.S_IMODE(os.stat(board.path).st_mode) & 0o077 == 0
    assert stat.S_IMODE(os.stat(sf.gate_path(board.path)).st_mode) & 0o077 == 0


def test_append_refuses_without_fcntl(tmp_path, monkeypatch):
    monkeypatch.setattr(sf, "fcntl", None)
    with pytest.raises(sf.FindingsError, match="fcntl"):
        _board(tmp_path).record(sf.Finding(key="k", agent="a", summary="x"))
    assert not (tmp_path / "findings.jsonl").exists()


_WRITER = r"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location("sf_writer", sys.argv[1])
sf = importlib.util.module_from_spec(spec); sys.modules["sf_writer"] = sf; spec.loader.exec_module(sf)
board = sf.FindingsBoard(sys.argv[2])
print("ready", flush=True)
board.record(sf.Finding(key="from-child", agent="child", summary="x"))
print("done", flush=True)
"""


def test_append_waits_for_the_exclusive_lock_across_processes(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text("")
    holder = os.open(path, os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX)                     # another racer is mid-append
    child = subprocess.Popen([sys.executable, "-I", "-c", _WRITER, str(SF_PATH), str(path)],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        time.sleep(0.6)
        assert path.read_text() == "", "the child appended while another process held the lock"
        assert child.poll() is None
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
    assert child.stdout.readline().strip() == "done"
    assert child.wait(timeout=20) == 0
    assert [e.key for e in sf.FindingsBoard(path).entries()] == ["from-child"]


def test_concurrent_appends_are_line_atomic(tmp_path):
    board = _board(tmp_path)
    writers, per_writer = 8, 25

    def work(w):
        for i in range(per_writer):
            board.record(sf.Finding(key=f"w{w}-{i}", agent=f"agent-{w}", summary="x" * 50,
                                    kind="note"))

    threads = [threading.Thread(target=work, args=(w,)) for w in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    entries = board.entries()                               # raises if any line is torn
    assert len(entries) == writers * per_writer
    assert len({(e.key) for e in entries}) == writers * per_writer


def test_accept_mirrors_a_candidate_record_to_the_ledger(tmp_path):
    work = tmp_path / "work"
    board = _board(tmp_path, gate=sf.regex_gate(r"tok-\w+"), ledger_workdir=work)
    with pytest.raises(sf.AcceptanceRejected):
        board.accept(sf.Finding(key="flag", agent="a", summary="bad", candidate="nope"))
    assert list(ledger.read(work)) == []                     # a rejection is not mirrored
    board.accept(sf.Finding(key="flag", agent="a5", summary="ok", candidate="tok-yes"))
    [rec] = list(ledger.read(work))
    assert rec["event"] == "candidate" and rec["engine"] == "tools.shared_findings"
    assert (rec["key"], rec["agent"], rec["candidate"], rec["gate"]) == ("flag", "a5", "tok-yes", "regex")
    # without ledger_workdir nothing is mirrored
    plain = _board(tmp_path / "p", gate=sf.regex_gate(r"tok-\w+"))
    plain.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="tok-yes"))
    assert len(list(ledger.read(work))) == 1


# ------------------------------------------------------------------------------- loud failures

def test_malformed_log_line_fails_loudly(tmp_path):
    path = tmp_path / "findings.jsonl"
    board = sf.FindingsBoard(path)
    board.record(sf.Finding(key="ok", agent="a", summary="good"))
    with path.open("a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    with pytest.raises(sf.FindingsError, match=r"findings.jsonl:2: not JSON"):
        board.entries()


def test_wrong_schema_is_rejected(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text(json.dumps({"schema": 99, "key": "k", "agent": "a"}) + "\n", encoding="utf-8")
    with pytest.raises(sf.FindingsError, match="unsupported findings schema"):
        sf.FindingsBoard(path).entries()


def test_finding_field_validation():
    with pytest.raises(sf.FindingsError, match="key"):
        sf.Finding(key="", agent="a", summary="x")
    with pytest.raises(sf.FindingsError, match="kind"):
        sf.Finding(key="k", agent="a", summary="x", kind="bogus")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
