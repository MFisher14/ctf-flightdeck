#!/usr/bin/env python3
"""The deterministic multi-stage Windows-DFIR linker (solvers/toolkits/dfir_chain.py).

  .venv/bin/python tests/test_dfir_multistage_chain.py

Offline: no Game Master request, no token; the labels ledger is pointed at a throwaway
CTF_WORKDIR so an unsure answer is deterministic. The fixtures are JSON event logs the
windows.py reader parses (json_events), in two members -- stage 1 names the account, stage 2
logs its logon and the process it spawns.

It proves the never-wrong boundary the capstone depends on:

  * a GROUNDED link resolves to the EXACT value a reader read (the spawned image path), PLAIN;
  * the link only SELECTS a record -- two records matching equally (two accounts at the first
    success instant, or two distinct spawned processes) is None, never a guess;
  * a chained inference with no backing record (the file a process wrote, when no file-write was
    logged) is None;
  * the SELECTION itself (which account) is an author-named value -> UNSURE candidate, not plain;
  * a single-stage question with no cross-stage link to resolve is None (a reader's job).
"""
import json
import os
import sys
import tempfile
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_dfir_chain_")
os.environ.pop("CTF_TOKEN", None)
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
import labels                                   # noqa: E402

_spec = importlib.util.spec_from_file_location("dfir_chain", REPO / "solvers" / "toolkits" / "dfir_chain.py")
dfir_chain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dfir_chain)

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


IMAGE = r"C:\Windows\Temp\evil.exe"            # the exact spelling windows.py will read back
PID = "0x4d2"


def _ev(eid, t, data, computer="HOST1", record=1):
    return {"EventID": eid, "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
            "Computer": computer, "TimeCreated": t, "EventRecordID": record, "EventData": data}


def _member(events):
    return json.dumps(events).encode()


# --- Stage 1 (names the account) + stage 2 (its logon + spawned process), the clean chain ------
STAGE1 = _member([
    _ev(4625, "2026-02-01T09:00:01Z", {"TargetUserName": "bob", "IpAddress": "10.0.0.9"}, record=1),
    _ev(4625, "2026-02-01T09:00:02Z", {"TargetUserName": "bob", "IpAddress": "10.0.0.9"}, record=2),
    _ev(4625, "2026-02-01T09:00:03Z", {"TargetUserName": "bob", "IpAddress": "10.0.0.9"}, record=3),
    _ev(4624, "2026-02-01T09:00:07Z", {"TargetUserName": "alice", "TargetLogonId": "0x1a2b",
                                       "LogonType": "3"}, record=4),
])
STAGE2 = _member([
    _ev(4688, "2026-02-01T09:00:11Z", {"SubjectUserName": "alice", "SubjectLogonId": "0x1a2b",
                                       "NewProcessName": IMAGE, "NewProcessId": PID}, record=5),
])
CLEAN = {"stage1_security.json": STAGE1, "stage2_sysmon.json": STAGE2}

Q_IMAGE = {"qid": "img", "answer_id": "img",
           "question": "What is the image path of the process spawned by the account that logged on "
                       "after the failed logons?", "answer_format": {"kind": "exact_text"}}
Q_FILE = {"qid": "file", "answer_id": "file",
          "question": "What file did the process spawned by the account that logged on after the "
                      "failed logons write to disk?", "answer_format": {"kind": "exact_text"}}
Q_ACCT = {"qid": "acct", "answer_id": "acct",
          "question": "Which account logged on after the failed logons?",
          "answer_format": {"kind": "exact_text"}}
Q_SINGLE = {"qid": "single", "answer_id": "single",
            "question": "What is the image path?", "answer_format": {"kind": "exact_text"}}


def test_grounded_link_is_plain_and_exact():
    out = dfir_chain.solve_set([Q_IMAGE], CLEAN, {})
    val = out["img"]
    check("the stage-2 image path resolves via the carried account A to the EXACT path windows.py read",
          val == IMAGE, val)
    check("that grounded value is PLAIN (not an unsure / candidate string)",
          isinstance(val, str) and not labels.is_unsure(val) and not labels.is_candidate(val), val)
    rep = dfir_chain.chain_report(CLEAN)
    check("chain_report carries the account-after-failures pivot (account A)",
          rep["links"]["account_after_failures"] == "alice", rep["links"])
    check("chain_report links the pivot to the exact spawned image",
          rep["links"].get("spawned_image") == IMAGE, rep["links"])


def test_ambiguous_account_is_none():
    # Two accounts log on at the SAME first instant after the failures -> the link matches two
    # records equally -> None (never a pick of one).
    stage1 = _member([
        _ev(4625, "2026-02-01T09:00:01Z", {"TargetUserName": "bob"}, record=1),
        _ev(4625, "2026-02-01T09:00:02Z", {"TargetUserName": "bob"}, record=2),
        _ev(4624, "2026-02-01T09:00:07Z", {"TargetUserName": "alice", "TargetLogonId": "0x1a2b"}, record=3),
        _ev(4624, "2026-02-01T09:00:07Z", {"TargetUserName": "mallory", "TargetLogonId": "0x9f9f"}, record=4),
    ])
    files = {"stage1.json": stage1, "stage2.json": STAGE2}
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("an ambiguous link (two accounts match equally) resolves to None", out["img"] is None, out["img"])
    rep = dfir_chain.chain_report(files)
    check("chain_report marks the ambiguous pivot, it does not pick one",
          rep["links"]["account_after_failures"] == "<ambiguous>", rep["links"])


def test_distinct_accounts_at_different_times_is_none():
    # THE never-guess hole this fix closes. A service/machine 4624 almost always lands FIRST on a
    # real host after a brute-force burst, then the human logs on later. Taking the FIRST success
    # instant guessed the service account and fed its spawned (benign) image to the PLAIN path.
    # Two distinct accounts at DIFFERENT times, and neither is the sole targeted-and-succeeded
    # account -> AMBIGUOUS -> None, never a plain guess.
    benign = r"C:\Program Files\Monitor\agent.exe"
    stage1 = _member([
        _ev(4625, "2026-02-01T09:00:01Z", {"TargetUserName": "bob"}, record=1),
        _ev(4625, "2026-02-01T09:00:02Z", {"TargetUserName": "bob"}, record=2),
        _ev(4624, "2026-02-01T09:00:05Z", {"TargetUserName": "svc", "TargetLogonId": "0x3e7",
                                           "LogonType": "5"}, record=3),
        _ev(4624, "2026-02-01T09:00:09Z", {"TargetUserName": "carol", "TargetLogonId": "0x1a2b",
                                           "LogonType": "3"}, record=4),
    ])
    stage2 = _member([
        _ev(4688, "2026-02-01T09:00:06Z", {"SubjectUserName": "svc", "SubjectLogonId": "0x3e7",
                                           "NewProcessName": benign, "NewProcessId": "0x111"}, record=5),
        _ev(4688, "2026-02-01T09:00:11Z", {"SubjectUserName": "carol", "SubjectLogonId": "0x1a2b",
                                           "NewProcessName": IMAGE, "NewProcessId": PID}, record=6),
    ])
    files = {"s1.json": stage1, "s2.json": stage2}
    rep = dfir_chain.chain_report(files)
    check("distinct accounts at different times after the burst -> ambiguous pivot (not the first instant)",
          rep["links"]["account_after_failures"] == "<ambiguous>", rep["links"])
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("the spawned-image answer is None, not the benign image of the first account (no wrong plain)",
          out["img"] is None, out["img"])


def test_targeted_account_disambiguates_distinct_accounts():
    # Multiple accounts logged on after the burst, but exactly one of them is the account the 4625
    # burst TARGETED -- a byte-grounded disambiguator. The pivot is that targeted account, and its
    # spawned image is plain and exact.
    stage1 = _member([
        _ev(4625, "2026-02-01T09:00:01Z", {"TargetUserName": "alice"}, record=1),
        _ev(4625, "2026-02-01T09:00:02Z", {"TargetUserName": "alice"}, record=2),
        _ev(4624, "2026-02-01T09:00:05Z", {"TargetUserName": "HOST1$", "TargetLogonId": "0x3e7",
                                           "LogonType": "5"}, record=3),
        _ev(4624, "2026-02-01T09:00:09Z", {"TargetUserName": "alice", "TargetLogonId": "0x1a2b",
                                           "LogonType": "3"}, record=4),
    ])
    files = {"s1.json": stage1, "s2.json": STAGE2}
    rep = dfir_chain.chain_report(files)
    check("the targeted-and-succeeded account is the pivot even amid machine-account noise",
          rep["links"]["account_after_failures"] == "alice", rep["links"])
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("that grounded pivot resolves the exact spawned image, plain",
          out["img"] == IMAGE and not labels.is_unsure(out["img"]), out["img"])


def test_lone_noninteractive_success_is_not_falsely_declined():
    # NO false None on a genuine single-value case. A lone type-8 (NetworkCleartext) success after
    # the burst is still the one account that got in; a logon-type allowlist would wrongly decline
    # it. There is deliberately no such allowlist.
    stage1 = _member([
        _ev(4625, "2026-02-01T09:00:01Z", {"TargetUserName": "bob"}, record=1),
        _ev(4624, "2026-02-01T09:00:07Z", {"TargetUserName": "carol", "TargetLogonId": "0x55",
                                           "LogonType": "8"}, record=2),
    ])
    stage2 = _member([
        _ev(4688, "2026-02-01T09:00:11Z", {"SubjectUserName": "carol", "SubjectLogonId": "0x55",
                                           "NewProcessName": IMAGE, "NewProcessId": PID}, record=3),
    ])
    files = {"s1.json": stage1, "s2.json": stage2}
    rep = dfir_chain.chain_report(files)
    check("a lone type-8 success is the pivot (no logon-type allowlist -> no false None)",
          rep["links"]["account_after_failures"] == "carol", rep["links"])
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("its spawned image resolves plain and exact (genuine single value preserved)",
          out["img"] == IMAGE and not labels.is_unsure(out["img"]), out["img"])


def test_ungrounded_field_question_is_none():
    # Questions worded with 'process' + a spawn-ish verb but asking for a field the index holds NO
    # record for (a parent process, a file the process READ, a loaded DLL) must not get the spawned
    # image as a plain answer. The linker declines -> None.
    for qid, qtext in (
        ("parent", "What is the parent process of the program the account that logged on after the "
                   "failed logons ran?"),
        ("read", "Which file did the process spawned by the account that logged on after the failed "
                 "logons read?"),
        ("module", "What DLL did the process started by the account that logged on after the failed "
                   "logons load?"),
    ):
        out = dfir_chain.solve_set([{"qid": qid, "answer_id": qid, "question": qtext,
                                     "answer_format": {"kind": "exact_text"}}], CLEAN, {})
        check(f"an ungrounded field question ({qid}) resolves to None, not the spawned image",
              out[qid] is None, out[qid])


def test_ambiguous_output_record_is_none():
    # The account resolves cleanly, but two DISTINCT processes ran in its session -> the output
    # selection matches two records equally -> None.
    stage2 = _member([
        _ev(4688, "2026-02-01T09:00:11Z", {"SubjectUserName": "alice", "SubjectLogonId": "0x1a2b",
                                           "NewProcessName": IMAGE, "NewProcessId": PID}, record=5),
        _ev(4688, "2026-02-01T09:00:12Z", {"SubjectUserName": "alice", "SubjectLogonId": "0x1a2b",
                                           "NewProcessName": r"C:\Windows\System32\cmd.exe",
                                           "NewProcessId": "0x999"}, record=6),
    ])
    files = {"stage1.json": STAGE1, "stage2.json": stage2}
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("two distinct spawned processes (output records match equally) resolve to None",
          out["img"] is None, out["img"])


def test_nongrounded_inference_is_none():
    # The chain resolves to a single process, but NO file-write record was logged, so the file it
    # wrote is a non-grounded inference -> None.
    out = dfir_chain.solve_set([Q_FILE], CLEAN, {})
    check("a chained inference with no backing parsed record (the file written) resolves to None",
          out["file"] is None, out["file"])


def test_selection_is_unsure_not_plain():
    out = dfir_chain.solve_set([Q_ACCT], CLEAN, {})
    val = out["acct"]
    check("the author-named selection (which account) is UNSURE, a candidate pick",
          labels.is_candidate(val), val)
    parsed = labels.parse(val)
    check("the unsure account candidate carries the exact parsed value A",
          parsed is not None and any(v == "alice" for _n, v in parsed.options), val)


def test_single_stage_question_declined():
    # No failed-logon pivot, no named account -> no cross-stage link -> the linker declines (None),
    # leaving the single-artifact question to its own reader.
    out = dfir_chain.solve_set([Q_SINGLE], CLEAN, {})
    check("a single-stage question with no cross-stage link to resolve is None", out["single"] is None, out["single"])


def test_empty_delivery_is_safe():
    out = dfir_chain.solve_set([Q_IMAGE], {}, {})
    check("an empty delivery yields None and does not raise", out["img"] is None, out["img"])
    rep = dfir_chain.chain_report({})
    check("chain_report on an empty delivery is a well-formed empty report",
          rep["event_count"] == 0 and rep["links"]["account_after_failures"] is None, rep)


def test_readers_load_read_only():
    # Every named per-artifact reader imports read-only under its private name (or is None if an
    # optional dependency is missing); windows.py, the chain core, must load.
    for name in ("windows", "registry", "memory", "forensics", "email", "cloudlogs"):
        mod = dfir_chain._reader(name)
        if name == "windows":
            check("the windows.py reader (chain core) loads read-only", mod is not None)
        else:
            check(f"the {name} reader import does not raise (None is tolerated)", True)
    # The standard-library email package must still be the real one (toolkits never on sys.path).
    import email
    check("the standard-library email package is not shadowed by the email toolkit",
          "email/__init__" in (email.__file__ or ""), email.__file__)


def test_enrichment_mixed_delivery_keeps_the_chain():
    # A multi-member delivery that also carries a non-Windows member (a cloud/identity log) must
    # not disturb the strict event chain, and chain_report should span the extra stage.
    cloudlog = json.dumps({"Records": [
        {"eventName": "ConsoleLogin", "userIdentity": {"userName": "alice", "type": "IAMUser"},
         "sourceIPAddress": "203.0.113.7", "eventTime": "2026-02-01T09:05:00Z",
         "eventSource": "signin.amazonaws.com", "awsRegion": "us-east-1"}]}).encode()
    files = dict(CLEAN)
    files["identity_cloudtrail.json"] = cloudlog
    out = dfir_chain.solve_set([Q_IMAGE], files, {})
    check("a mixed (Windows + cloud) delivery still resolves the grounded image path exactly",
          out["img"] == IMAGE, out["img"])
    rep = dfir_chain.chain_report(files)
    check("chain_report lists 'windows' among its sources", "windows" in rep["sources"], rep["sources"])


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print()
    if FAILED:
        print(f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
        return 1
    print("all dfir_chain never-wrong checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
