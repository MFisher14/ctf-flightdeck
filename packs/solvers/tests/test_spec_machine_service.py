"""B-057: the service half of the spec-driven machine: the gated play against a loopback audit
service, the engine entry (solve), the manifest routes and the `ctf machine` command.

The service is tests/spec_machine_fixtures.AuditService on 127.0.0.1: it sends random programs,
checks every answer against an independent reference interpreter and closes on the first wrong one.
No wall-clock upper bound is asserted anywhere; the one pause (a round sent in two writes) only has
to be long enough for the client to see the first half alone, and the test passes either way.
"""
from __future__ import annotations

import datetime as dt
import json
import random
import select
import socket
import subprocess
import sys
import types
from pathlib import Path

import pytest

import netplay
import spec_machine as sm
from ctf import cli, event, paths, scope
from ctf.engines import manifest, router
from spec_machine_fixtures import FLAG, AuditService, random_round, reference, tally, TALLY


def rounds(n: int, seed: int = 9141):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        program, tape = random_round(rng)
        out.append((program, tape, reference(program, tape)))
    return out


def spec_file(folder, data=None, name="tally.machine.json"):
    path = folder / name
    path.write_text(json.dumps(TALLY if data is None else data), encoding="utf-8")
    return path


def loopback_profile(scope_entries=("127.0.0.0/8",)):
    return event.parse({
        "slug": "b057-loopback", "name": "B-057 loopback",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b057-platform.test"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_entries)},
    }, src="tests/test_spec_machine_service.py")


# ------------------------------------------------------------------------------------------------- play

def test_play_answers_every_round_and_reads_the_flag():
    service = AuditService(rounds(25))
    played = sm.play(sm.parse_spec(TALLY), service.host, service.port, timeout=30.0, quiet=0.2)
    service.join()
    assert service.error is None
    assert played.flag == FLAG and played.rounds == 25
    assert [a.strip() for a in service.answers] == [want for _, _, want in service.rounds]
    assert played.report.ok and played.report.total == 2


def test_play_answers_a_round_that_arrives_in_two_writes():
    service = AuditService(rounds(4, seed=3), split_at=30, pause=0.4)
    played = sm.play(sm.parse_spec(TALLY), service.host, service.port, timeout=30.0, quiet=0.05)
    service.join()
    assert service.error is None and played.flag == FLAG and played.rounds == 4
    assert len(service.answers) == 4                      # one answer per round, never one per fragment


def test_a_wrong_machine_is_caught_by_the_service_and_reported():
    """The spec passes its own (too thin) examples, so the gate opens; the service then disagrees."""
    wrong = tally(quirks={"shift_mask": 31}, examples=[TALLY["examples"][0]])
    script = [("put r1 3\nsay r1", [], "3"),
              ("put r1 1\nput r2 17\nlsh r0 r1 r2\nsay r0", [], "2"),        # the real machine masks with 15
              ("say r0", [], "0")]
    service = AuditService(script)
    played = sm.play(sm.parse_spec(wrong), service.host, service.port, timeout=30.0, quiet=0.2)
    service.join()
    assert played.flag is None and played.rounds == 2
    assert service.answers == ["3", "0"]                  # the second answer was wrong; the third round never came
    assert "WRONG. session closed." in played.last_text


def test_the_gate_refuses_before_any_connection():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    try:
        failing = sm.parse_spec(tally(quirks={"div_zero": 0}))
        with pytest.raises(sm.GateRefused, match="1/2 worked examples reproduce; refusing to play"):
            sm.play(failing, host, port, timeout=5.0)
        with pytest.raises(sm.GateRefused, match="no worked examples"):
            sm.play(sm.parse_spec(tally(examples=[])), host, port, timeout=5.0)
        # a connect() would have completed against the listening socket and be waiting in its queue
        assert select.select([listener], [], [], 0)[0] == []
        # the same listener does see a client that is allowed to connect: the check above can fail
        probe = socket.create_connection((host, port), timeout=5.0)
        try:
            assert select.select([listener], [], [], 5.0)[0] == [listener]
        finally:
            probe.close()
    finally:
        listener.close()


def test_play_checks_the_framing_and_the_scope_before_any_socket(monkeypatch):
    def no_socket(*a, **kw):
        raise AssertionError("a socket was opened")
    monkeypatch.setattr(socket, "create_connection", no_socket)
    no_prompt = tally()
    del no_prompt["framing"]["prompt"]
    with pytest.raises(sm.SpecError, match=r"\[framing\] with `prompt`"):
        sm.play(sm.parse_spec(no_prompt), "127.0.0.1", 9, timeout=1.0)
    spec = sm.parse_spec(TALLY)
    with pytest.raises(scope.OutOfScope):
        sm.play(spec, "audit.example.org", 9141, timeout=1.0)        # not in the suite profile's scope
    with pytest.raises(scope.OutOfScope, match="spec_machine target 127.0.0.1:9"):
        sm.play(spec, "127.0.0.1", 9, timeout=1.0, profile=loopback_profile(["10.0.0.0/8"]))


def test_a_round_that_cannot_be_answered_raises_and_sends_nothing():
    script = [("say r0", [], "0"), ("frobnicate r1", [], "?"), ("say r0", [], "0")]
    service = AuditService(script)
    with pytest.raises(sm.ProgramError, match="unknown instruction 'frobnicate'"):
        sm.play(sm.parse_spec(TALLY), service.host, service.port, timeout=30.0, quiet=0.2)
    service.join()
    assert service.answers == ["0"]                       # nothing was sent for the second round


def test_play_uses_the_netplay_driver_and_the_spec_fuel(monkeypatch):
    calls = []
    real = netplay.run_loop

    def spy(conn, handler, **kw):
        calls.append((type(handler).__name__, kw["delims"], kw["max_rounds"]))
        return real(conn, handler, **kw)
    monkeypatch.setattr(netplay, "run_loop", spy)
    service = AuditService(rounds(2, seed=1))
    assert sm.play(sm.parse_spec(TALLY), service.host, service.port, timeout=30.0, quiet=0.2, max_rounds=77).flag == FLAG
    assert calls == [("RoundHandler", [b"OUTPUT>"], 77)]
    # an explicit fuel reaches the rounds: a loop that needs more than 10 instructions stops the play
    service = AuditService([("times 3\n times 3\n say r0\n done\ndone", [], "0 0 0 0 0 0 0 0 0")])
    with pytest.raises(sm.FuelExhausted):
        sm.play(sm.parse_spec(TALLY), service.host, service.port, timeout=30.0, quiet=0.2, fuel=10)
    service.join()
    assert service.answers == []


def test_play_loads_this_checkouts_netplay_never_one_on_the_path(tmp_path, monkeypatch):
    # `python -m ctf machine play` run from a challenge folder: that folder is on sys.path, and a
    # netplay.py planted in it must never be imported in place of tools/netplay.py.
    planted = tmp_path / "planted"
    planted.mkdir()
    marker = tmp_path / "planted-ran"
    (planted / "netplay.py").write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(planted))
    monkeypatch.delitem(sys.modules, "netplay", raising=False)
    monkeypatch.delitem(sys.modules, "spec_machine_netplay", raising=False)
    mod = sm._netplay()
    assert not marker.exists()
    assert Path(mod.__file__).resolve() == (paths.repo_root() / "tools" / "netplay.py").resolve()
    assert callable(mod.run_loop) and callable(mod.connect)
    # an imported `netplay` that is some other file is not reused either
    fake = types.ModuleType("netplay")
    fake.__file__ = str(planted / "netplay.py")
    monkeypatch.setitem(sys.modules, "netplay", fake)
    assert sm._netplay() is mod
    # the repo copy, once imported under its own name (as the tests do), is the one used
    monkeypatch.setitem(sys.modules, "netplay", netplay)
    assert sm._netplay() is netplay


# ------------------------------------------------------------------------------------------------ solve

def test_solve_without_a_spec_or_with_several_is_blocked(tmp_path):
    profile = loopback_profile()
    none = sm.solve(tmp_path, profile)
    assert none.status == "blocked" and none.engine == "toolkits.spec_machine"
    assert "no machine spec (*.machine.toml or *.machine.json)" in none.notes and "ctf machine init" in none.notes
    spec_file(tmp_path)
    (tmp_path / "solve").mkdir()
    spec_file(tmp_path / "solve", name="other.machine.toml")
    (tmp_path / ".hidden").mkdir()
    spec_file(tmp_path / ".hidden", name="ignored.machine.toml")
    assert [p.name for p in sm.find_specs(tmp_path)] == ["other.machine.toml", "tally.machine.json"]
    several = sm.solve(tmp_path, profile)
    assert several.status == "blocked" and "solve/other.machine.toml, tally.machine.json" in several.notes
    picked = sm.solve(tmp_path, profile, spec="tally.machine.json")
    assert picked.status == "none"


def test_solve_reports_a_spec_that_does_not_load_and_a_closed_gate(tmp_path):
    profile = loopback_profile()
    bad = spec_file(tmp_path, tally(word_bits=99))
    broken = sm.solve(tmp_path, profile)
    assert broken.status == "blocked" and "spec.word_bits: must be an integer 1..64" in broken.notes
    bad.unlink()
    spec_file(tmp_path, tally(quirks={"div_zero": 0}))
    closed = sm.solve(tmp_path, profile, host="127.0.0.1", port=9)       # nothing is contacted
    assert closed.status == "unsure" and closed.flags == ()
    assert "conformance gate closed: 1/2 worked examples reproduce" in closed.notes
    (ev,) = closed.evidence
    assert (ev.kind, ev.path) == ("conformance", "tally.machine.json")
    assert ev.detail == "zero rules: expected '65535 9', got '0 9'"
    (tmp_path / "tally.machine.json").unlink()
    spec_file(tmp_path, tally(examples=[]))
    bare = sm.solve(tmp_path, profile)
    assert bare.status == "unsure" and "it has no worked examples" in bare.notes


def test_solve_with_passing_examples_and_no_service(tmp_path):
    spec_file(tmp_path)
    r = sm.solve(tmp_path, loopback_profile())
    assert r.status == "none" and r.flags == ()
    assert "2/2 worked examples reproduce; no service named" in r.notes
    assert [(e.kind, e.detail, e.path) for e in r.evidence] == [
        ("conformance", "2/2 worked examples reproduce", "tally.machine.json")]
    # half a target is a named error, not a quiet "no service": nothing is contacted
    for half, missing in (({"host": "127.0.0.1"}, "without a port"), ({"port": 9141}, "without a host")):
        r = sm.solve(tmp_path, loopback_profile(), **half)
        assert r.status == "blocked" and "half a service target" in r.notes and missing in r.notes
        assert [e.detail for e in r.evidence] == ["2/2 worked examples reproduce"]
    assert not (tmp_path / "recon").exists()
    typed = sm.solve(tmp_path, loopback_profile(), host="127.0.0.1", port="9141")
    assert typed.status == "blocked" and "port an integer" in typed.notes


def test_solve_plays_the_service_to_the_flag(tmp_path):
    spec_file(tmp_path)
    service = AuditService(rounds(6, seed=11))
    r = sm.solve(tmp_path, loopback_profile(), host=service.host, port=service.port, timeout=30.0)
    service.join()
    assert service.error is None
    assert r.status == "solved" and r.flags == (FLAG,) and r.engine == "toolkits.spec_machine"
    kinds = {e.kind: e for e in r.evidence}
    assert kinds["wire"].detail == f"answered 6 round(s) of {service.host}:{service.port}"
    assert kinds["wire"].path == "recon/spec_machine/session.log"
    log = (tmp_path / "recon" / "spec_machine" / "session.log").read_text(encoding="utf-8")
    assert log.count("=== round ") == 6 and f"OUTPUT> {service.rounds[5][2]}\n" in log


def test_solve_without_a_flag_and_out_of_scope(tmp_path):
    spec_file(tmp_path, tally(quirks={"shift_mask": 31}, examples=[TALLY["examples"][0]]))
    service = AuditService([("put r1 1\nput r2 17\nlsh r0 r1 r2\nsay r0", [], "2")])
    lost = sm.solve(tmp_path, loopback_profile(), host=service.host, port=service.port, timeout=30.0)
    service.join()
    assert lost.status == "none" and lost.flags == ()
    assert "answered 1 round(s) and the service sent no flag" in lost.notes and "WRONG. session closed." in lost.notes
    out = sm.solve(tmp_path, loopback_profile(["10.0.0.0/8"]), host="127.0.0.1", port=9)
    assert out.status == "blocked" and "outside the event's live-service scope" in out.notes
    service = AuditService([("frobnicate", [], "")])
    stuck = sm.solve(tmp_path, loopback_profile(), host=service.host, port=service.port, timeout=30.0)
    service.join()
    assert stuck.status == "unsure" and "ProgramError" in stuck.notes and "nothing was guessed" in stuck.notes
    assert service.answers == []


# --------------------------------------------------------------------------------- manifest and routing

def test_the_manifest_routes_a_spec_file_and_the_challenge_wording(tmp_path):
    mf = {m.id: m for m in manifest.discover()}["toolkits.spec_machine"]
    assert mf.entry_raw == "solvers.toolkits.spec_machine:solve" and mf.has("executes") and mf.intake is None
    wording = ("Connect to the audit service, build an interpreter that behaves as the specification and "
               "the examples describe, and answer every program.")
    hits = [h.manifest.id for h in router.route("misc", wording.lower())]
    assert "toolkits.spec_machine" in hits
    assert "toolkits.spec_machine" not in [h.manifest.id for h in router.route("misc", "a png with a secret")]
    # generic wording that fits any VM or puzzle brief does not pull this engine in
    generic = "a custom register machine; the readme has worked examples of its bytecode"
    for category in ("misc", "reverse"):
        assert "toolkits.spec_machine" not in [h.manifest.id for h in router.route(category, generic)]
    assert [h.priority for h in router.route("misc", wording.lower()) if h.manifest.id == "toolkits.spec_machine"] == [60]
    spec_file(tmp_path, name="audit.machine.toml")
    by_file = router.route("crypto", "", files_dir=tmp_path)
    assert by_file[0].manifest.id == "toolkits.spec_machine" and by_file[0].priority == 72


def test_ctf_run_calls_the_engine_entry(tmp_path):
    spec_file(tmp_path)
    r = subprocess.run([sys.executable, "-m", "ctf", "run", "--no-ledger", "toolkits.spec_machine", str(tmp_path),
                        "--event", "csctf"], cwd=paths.repo_root(), capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    result = json.loads(r.stdout.strip().splitlines()[-1])
    assert result["status"] == "none" and result["engine"] == "toolkits.spec_machine"
    assert "2/2 worked examples reproduce" in result["notes"]


# ---------------------------------------------------------------------------------------------- the CLI

def test_cli_init_check_and_run(tmp_path, capsys):
    assert cli.main(["machine", "init", str(tmp_path)]) == 0
    made = tmp_path / "machine.machine.toml"
    assert capsys.readouterr().out.strip() == str(made) and made.read_text(encoding="utf-8") == sm.TEMPLATE
    assert cli.main(["machine", "init", str(tmp_path)]) == 2
    assert "not overwriting" in capsys.readouterr().err

    assert cli.main(["machine", "check", str(made)]) == 0
    assert capsys.readouterr().out == "ok    3/3 worked examples reproduce\n"

    program = tmp_path / "p.txt"
    program.write_text("in r1\nin r2\nadd r0 r1 r2\nout r0\nout r2\n", encoding="utf-8")
    assert cli.main(["machine", "run", str(made), str(program), "--input", "65535, 3"]) == 0
    assert capsys.readouterr().out == "2 3\n"
    assert cli.main(["machine", "run", str(made), str(program), "--input", "1 2", "--trace"]) == 0
    got = capsys.readouterr()
    assert got.out == "3 2\n"
    assert [ln.split()[:3] for ln in got.err.splitlines()][:3] == [["1", "in", "r1"], ["2", "in", "r2"], ["3", "add", "r0"]]
    assert "r0=3 r1=1 r2=2" in got.err.splitlines()[2]


def test_cli_check_reports_failures_and_errors(tmp_path, capsys):
    failing = spec_file(tmp_path, tally(quirks={"div_zero": 0}))
    assert cli.main(["machine", "check", str(failing)]) == 1
    assert capsys.readouterr().out == ("FAIL #2 zero rules: expected '65535 9', got '0 9'\n"
                                       "FAIL  1/2 worked examples reproduce\n")
    assert cli.main(["machine", "check", str(failing), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report == {"ok": False, "total": 2, "passed": 1, "failures": [
        {"index": 2, "name": "zero rules", "expected": "65535 9", "got": "0 9", "error": None}]}
    bare = spec_file(tmp_path, tally(examples=[]), name="bare.machine.json")
    assert cli.main(["machine", "check", str(bare)]) == 1
    assert "cannot be played" in capsys.readouterr().out
    # --fuel reaches the examples
    assert cli.main(["machine", "check", str(spec_file(tmp_path, name="ok.machine.json")), "--fuel", "2"]) == 1
    assert "FuelExhausted" in capsys.readouterr().out
    assert cli.main(["machine", "check", str(tmp_path / "absent.machine.toml")]) == 2
    assert "SpecError" in capsys.readouterr().err
    broken = spec_file(tmp_path, tally(overflow="clip"), name="broken.machine.json")
    assert cli.main(["machine", "check", str(broken)]) == 2
    assert "spec.overflow: must be one of wrap, saturate, trap" in capsys.readouterr().err


def test_cli_run_exit_codes(tmp_path, capsys):
    spec = spec_file(tmp_path, tally(quirks={"div_zero": "trap"}))
    program = tmp_path / "p.txt"
    program.write_text("div r0 r1 r2\n", encoding="utf-8")
    assert cli.main(["machine", "run", str(spec), str(program)]) == 1
    assert "MachineTrap: line 1 `div r0 r1 r2`: division by zero" in capsys.readouterr().err
    program.write_text("times 9\n times 9\n  say r0\n done\ndone\n", encoding="utf-8")
    assert cli.main(["machine", "run", str(spec), str(program), "--fuel", "20"]) == 1
    assert "FuelExhausted" in capsys.readouterr().err
    program.write_text("frobnicate\n", encoding="utf-8")
    assert cli.main(["machine", "run", str(spec), str(program)]) == 2
    assert "ProgramError" in capsys.readouterr().err
    assert cli.main(["machine", "run", str(spec), str(tmp_path / "absent.txt")]) == 2
    assert "absent.txt" in capsys.readouterr().err


def test_cli_play(tmp_path, capsys):
    spec = spec_file(tmp_path)
    log = tmp_path / "session.log"
    service = AuditService(rounds(5, seed=21))
    assert cli.main(["machine", "play", str(spec), service.host, str(service.port), "--timeout", "30",
                     "--log", str(log)]) == 0
    service.join()
    got = capsys.readouterr()
    assert got.out == f"[+] FLAG  {FLAG}\n"
    assert "gate: 2/2 worked examples reproduce; answered 5 round(s)" in got.err
    assert log.read_text(encoding="utf-8").count("=== round ") == 5

    lying = spec_file(tmp_path, tally(quirks={"shift_mask": 31}, examples=[TALLY["examples"][0]]), name="lying.machine.json")
    service = AuditService([("put r1 1\nput r2 17\nlsh r0 r1 r2\nsay r0", [], "2")])
    assert cli.main(["machine", "play", str(lying), service.host, str(service.port), "--timeout", "30"]) == 1
    service.join()
    assert "[-] no flag; the service's last words: 'WRONG. session closed.'" in capsys.readouterr().out


def test_cli_play_refusals(tmp_path, capsys, monkeypatch):
    def no_socket(*a, **kw):
        raise AssertionError("a socket was opened")
    monkeypatch.setattr(socket, "create_connection", no_socket)
    failing = spec_file(tmp_path, tally(quirks={"div_zero": 0}))
    assert cli.main(["machine", "play", str(failing), "127.0.0.1", "9"]) == 4
    err = capsys.readouterr().err
    assert "FAIL #2 zero rules: expected '65535 9', got '0 9'" in err and "refused:" in err
    good = spec_file(tmp_path, name="good.machine.json")
    assert cli.main(["machine", "play", str(good), "audit.example.org", "9141"]) == 2
    assert "OutOfScope" in capsys.readouterr().err
