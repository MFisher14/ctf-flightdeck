"""B-102: the SOP/procedure-to-checker lane with a known-answer test.

No real model is ever called. The model-call tests start a stub `claude` script written into tmp_path
that answers in the `claude -p --output-format json` envelope; the subprocess runner and the KAT are
exercised for real against synthetic checkers built inside the test.
"""
from __future__ import annotations

import base64
import hashlib
import json
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import event
from ctf.result import SolverResult

import sop_checker as sc


# ----------------------------------------------------------------------------- a toy but real SOP

SOP_TEXT = textwrap.dedent("""\
    Reconciliation Standard Operating Procedure

    Step 1. Read the integer lines from data.txt; each line must be a base-10 integer.
    Step 2. The canonical report is each value doubled, one per line, LF-terminated, ending in
            exactly one LF. You shall not add trailing whitespace.
    Step 3. The report digest is the SHA-256 of the canonical report bytes.
    Step 4. The flag is CSCTF{ uppercase unpadded Base32 of the first 24 bytes of the digest }.

    Known-answer test (worked example): for the input "1\\n2\\n3\\n" the canonical report is
    "2\\n4\\n6\\n" and its SHA-256 digest is the value below. Reproduce this exactly before touching
    the real data; tolerance is zero.
    """)

NOT_SOP_TEXT = "A gentle story about a cat who found a warm spot by the window and slept all day.\n"


def _report(nums):
    return ("\n".join(str(n * 2) for n in nums) + "\n").encode()


def _digest(nums):
    return hashlib.sha256(_report(nums)).digest()


def _flag(nums):
    return "CSCTF{" + base64.b32encode(_digest(nums)[:24]).decode().rstrip("=") + "}"


CHECKER = textwrap.dedent("""\
    import sys, json, hashlib, base64
    data = open(sys.argv[1], "rb").read().decode()
    nums = [int(x) for x in data.split("\\n") if x.strip()]
    report = ("\\n".join(str(n * 2) for n in nums) + "\\n").encode()
    digest = hashlib.sha256(report).digest()
    flag = "CSCTF{" + base64.b32encode(digest[:24]).decode().rstrip("=") + "}"
    print(json.dumps({"kat_value": digest.hex(), "flag": flag}))
    """)


def proposal_dict(kat_expected, inputs=("data.txt",), checker=CHECKER):
    return {"is_sop": True, "checker": checker, "kat_input": "1\n2\n3\n",
            "kat_input_name": "data.txt", "kat_expected": kat_expected, "inputs": list(inputs)}


# ---------------------------------------------------------------------------------------- detection

def test_detect_sop_fires_on_a_procedure():
    sig = sc.detect_sop(SOP_TEXT)
    assert sig.is_sop
    assert sig.steps >= 4 and sig.normative >= 1 and sig.worked_example >= 1


def test_detect_sop_rejects_prose():
    assert not sc.detect_sop(NOT_SOP_TEXT).is_sop


def test_detect_sop_needs_more_than_numbered_steps():
    # ordered steps alone (a shopping list) are not an SOP: no normative, tolerance or worked example.
    plain = "1. milk\n2. eggs\n3. bread\n4. butter\n"
    sig = sc.detect_sop(plain)
    assert sig.steps >= 4 and not sig.is_sop


def test_find_sop_picks_the_document(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "reconciliation-sop.txt").write_text(SOP_TEXT)
    (tmp_path / "files" / "readme.txt").write_text(NOT_SOP_TEXT)
    path, text, sig = sc.find_sop(tmp_path)
    assert path is not None and path.name == "reconciliation-sop.txt" and sig.is_sop


def test_find_sop_none_when_absent(tmp_path):
    (tmp_path / "notes.txt").write_text(NOT_SOP_TEXT)
    path, _, sig = sc.find_sop(tmp_path)
    assert path is None and not sig.is_sop


# --------------------------------------------------------------------------- the subprocess runner

def test_run_checker_computes_values(tmp_path):
    inp = tmp_path / "data.txt"
    inp.write_text("4\n5\n")
    res = sc.run_checker(CHECKER, inp)
    assert res.returncode == 0 and not res.timed_out
    assert res.kat_value == _digest([4, 5]).hex()
    assert res.flag == _flag([4, 5])


def test_run_checker_times_out(tmp_path):
    inp = tmp_path / "x"
    inp.write_text("1\n")
    slow = "import time\ntime.sleep(5)\n"
    res = sc.run_checker(slow, inp, timeout=0.5)
    assert res.timed_out and res.kat_value is None


def test_run_checker_non_json_output(tmp_path):
    inp = tmp_path / "x"
    inp.write_text("1\n")
    res = sc.run_checker("print('not json')\n", inp)
    assert res.kat_value is None and "not JSON" in res.parse_error


def test_run_checker_is_isolated_from_the_input_dir(tmp_path):
    # A module planted next to the challenge input must not be importable: -I drops PYTHONPATH/user
    # site, the checker runs in an empty cwd, and its script dir holds only the checker.
    inp = tmp_path / "data.txt"
    inp.write_text("1\n")
    (tmp_path / "evil.py").write_text("raise SystemExit('planted code ran')\n")
    checker = textwrap.dedent("""\
        import sys, json
        try:
            import evil
            v = "LEAKED"
        except ImportError:
            v = "isolated"
        print(json.dumps({"kat_value": v, "flag": None}))
        """)
    res = sc.run_checker(checker, inp)
    assert res.kat_value == "isolated"


def test_run_checker_scrubs_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "super-secret-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
    inp = tmp_path / "x"
    inp.write_text("1\n")
    checker = textwrap.dedent("""\
        import os, sys, json
        print(json.dumps({"kat_value": "|".join(sorted(os.environ)), "flag": None}))
        """)
    res = sc.run_checker(checker, inp)
    keys = set((res.kat_value or "").split("|"))
    assert "CTF_TOKEN" not in keys and "AWS_SECRET_ACCESS_KEY" not in keys


# ----------------------------------------------------------------------------- envelope / proposal

def test_parse_cli_result_reads_the_envelope():
    env = json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": "hello"})
    text, err = sc._parse_cli_result("warning on stderr-ish line\n" + env)
    assert text == "hello" and err == ""


def test_parse_cli_result_refusal_and_error():
    ref = json.dumps({"type": "result", "result": "", "stop_reason": "refusal"})
    _, err = sc._parse_cli_result(ref)
    assert "declined" in err
    bad = json.dumps({"type": "result", "is_error": True, "subtype": "error_during_execution", "result": "x"})
    _, err2 = sc._parse_cli_result(bad)
    assert "error" in err2
    none, err3 = sc._parse_cli_result("not json at all")
    assert none is None and "no JSON" in err3


def test_parse_proposal_ok_and_tolerates_fences():
    p = sc.parse_proposal("```json\n" + json.dumps(proposal_dict("deadbeef")) + "\n```")
    assert isinstance(p, sc.Proposal) and p.kat_expected == "deadbeef" and p.inputs == ("data.txt",)


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.pop("checker"), "no checker"),
    (lambda d: d.pop("kat_input"), "no known-answer-test input"),
    (lambda d: d.pop("kat_expected"), "no known-answer-test expected"),
    (lambda d: d.__setitem__("is_sop", False), "not a procedure"),
])
def test_parse_proposal_blocks_on_incomplete_reply(mutate, needle):
    d = proposal_dict("deadbeef")
    mutate(d)
    out = sc.parse_proposal(json.dumps(d))
    assert isinstance(out, sc.Blocked) and needle in out.reason


def test_parse_proposal_blocks_on_non_json():
    out = sc.parse_proposal("this is not json")
    assert isinstance(out, sc.Blocked) and "not a JSON object" in out.reason


# ------------------------------------------------------------------- a stub claude for the model call

# The stub reads its reply and mode from files beside itself, NOT from the environment: the engine
# scrubs the model CLI's environment (as it should), so the stub cannot depend on an inherited var.
STUB = r'''#!{python}
import json, sys
from pathlib import Path
sys.stdin.read()                 # consume the prompt; it is data
here = Path(__file__).resolve().parent
mode = (here / "mode").read_text().strip() if (here / "mode").is_file() else "ok"
if mode == "refuse":
    print(json.dumps({{"type": "result", "result": "", "stop_reason": "refusal"}}))
    sys.exit(0)
if mode == "error":
    print(json.dumps({{"type": "result", "is_error": True, "subtype": "error_during_execution",
                       "result": "x"}}))
    sys.exit(1)
if mode == "garbage":
    print("no json here")
    sys.exit(0)
reply = (here / "reply.json").read_text()
print(json.dumps({{"type": "result", "subtype": "success", "is_error": False, "result": reply}}))
'''


@pytest.fixture
def stub_claude(tmp_path):
    b = tmp_path / "bin" / "claude-stub"
    b.parent.mkdir()
    b.write_text(STUB.format(python=sys.executable))
    b.chmod(b.stat().st_mode | stat.S_IXUSR)
    reply = b.parent / "reply.json"
    reply.write_text(json.dumps(proposal_dict(_digest([1, 2, 3]).hex())))
    mode = b.parent / "mode"
    return b, reply, mode


def test_propose_checker_parses_a_stub_reply(stub_claude):
    b, _, _ = stub_claude
    out = sc.propose_checker(SOP_TEXT, [{"name": "data.txt", "size": 4}],
                             {"regex": "x", "example": "CSCTF{...}"}, cli=str(b), model="sonnet")
    assert isinstance(out, sc.Proposal) and out.kat_expected == _digest([1, 2, 3]).hex()


def test_propose_checker_blocks_on_refusal(stub_claude):
    b, _, mode = stub_claude
    mode.write_text("refuse")
    out = sc.propose_checker(SOP_TEXT, [], {"regex": "x", "example": "y"}, cli=str(b), model="sonnet")
    assert isinstance(out, sc.Blocked) and "declined" in out.reason


def test_propose_checker_blocks_on_garbage(stub_claude):
    b, _, mode = stub_claude
    mode.write_text("garbage")
    out = sc.propose_checker(SOP_TEXT, [], {"regex": "x", "example": "y"}, cli=str(b), model="sonnet")
    assert isinstance(out, sc.Blocked)


# -------------------------------------------------------------------------------------------- solve

def _challenge(tmp_path, data="4\n5\n", sop=SOP_TEXT):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "files" / "reconciliation-sop.txt").write_text(sop)
    (d / "files" / "data.txt").write_text(data)
    return d


def test_solve_none_when_no_sop(tmp_path):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "files" / "notes.txt").write_text(NOT_SOP_TEXT)
    res = sc.solve(d, event.current(), cli="/nonexistent/claude")
    assert res.status == "none"


def test_solve_blocked_when_no_cli(tmp_path):
    d = _challenge(tmp_path)
    res = sc.solve(d, event.current(), cli="/nonexistent/claude")
    assert res.status == "blocked" and "CLI" in res.notes


def test_solve_solved_after_kat_passes(tmp_path, stub_claude):
    b, _, _ = stub_claude
    d = _challenge(tmp_path)
    res = sc.solve(d, event.current(), cli=str(b))
    assert res.status == "solved", res.notes
    assert list(res.flags) == [_flag([4, 5])]
    assert any(e.kind == "kat" for e in res.evidence)
    # the accepted checker is saved as a template under the workdir, not the repo
    assert any(e.kind == "template" for e in res.evidence)


def test_solve_saves_template_under_workdir(tmp_path, stub_claude):
    from ctf import paths
    b, _, _ = stub_claude
    d = _challenge(tmp_path)
    sc.solve(d, event.current(), cli=str(b))
    saved = paths.workdir() / "sop-checkers" / "chal" / "checker.py"
    assert saved.is_file() and "kat_value" in saved.read_text()
    assert not (Path(sc.__file__).parent / "sop-checkers").exists()   # never the repo


def test_solve_unsure_when_kat_fails(tmp_path, stub_claude):
    # The model states a wrong expected value: the checker's real output will not match it, the KAT
    # fails, and the flag must NOT be computed.
    b, reply, _ = stub_claude
    reply.write_text(json.dumps(proposal_dict("00" * 32)))      # wrong expected digest
    d = _challenge(tmp_path)
    res = sc.solve(d, event.current(), cli=str(b))
    assert res.status == "unsure" and "known-answer test" in res.notes.lower()
    assert not res.flags


def test_solve_unsure_when_checker_crashes_on_kat(tmp_path, stub_claude):
    b, reply, _ = stub_claude
    reply.write_text(json.dumps(proposal_dict(_digest([1, 2, 3]).hex(),
                                              checker="raise SystemExit('boom')\n")))
    d = _challenge(tmp_path)
    res = sc.solve(d, event.current(), cli=str(b))
    assert res.status == "unsure" and not res.flags


def test_solve_unsure_when_output_not_in_flag_format(tmp_path, stub_claude):
    b, reply, _ = stub_claude
    # a checker whose KAT value matches but whose flag is not in the event format: the KAT passed, so
    # the lane does not block, but the non-format value is not a flag, so the status is `unsure`.
    checker = textwrap.dedent("""\
        import sys, json, hashlib
        data = open(sys.argv[1], "rb").read().decode()
        nums = [int(x) for x in data.split("\\n") if x.strip()]
        report = ("\\n".join(str(n * 2) for n in nums) + "\\n").encode()
        digest = hashlib.sha256(report).hexdigest()
        print(json.dumps({"kat_value": digest, "flag": "not-a-flag"}))
        """)
    reply.write_text(json.dumps(proposal_dict(_digest([1, 2, 3]).hex(), checker=checker)))
    d = _challenge(tmp_path)
    res = sc.solve(d, event.current(), cli=str(b))
    assert res.status == "unsure" and not res.flags
    assert "not in the event flag format" in res.notes


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
