"""B-080: the in-band protocol recipe decoder lane (toolkits.inband_recipe).

    .venv/bin/python -m pytest tests/test_toolkits_inband_recipe.py

No real model and no real container. The model is a stub `claude` written into tmp_path that answers
in the `claude -p --output-format json` envelope (its reply comes from a file beside it: the engine
scrubs the CLI's environment). The decoder runs through the real tools/sandbox.py driven by a
stand-in docker program ($CTF_DOCKER, as tests/test_b136_vol_triage.py does it) that maps /drop and
/out to the test's folders and runs `python3 -I` there, or through a stub `sandbox` module where a
test is about what the engine hands the sandbox. The capture is synthetic (tests/b080_fixtures.py):
a toy relay protocol described in-band, with bad-checksum and valid forged copies of its DATA frame.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
import sys
from pathlib import Path

import pytest

import b080_fixtures as fx
from ctf import event
from solvers.toolkits import inband_recipe as ir
from solvers.toolkits import network_forensics as nf

PROFILE = event.parse({
    "slug": "b080-test", "name": "b080 test",
    "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
    "platform": {"kind": "ctfd", "base_url": "https://board.b080.test"},
    "flag": {"prefixes": ["CSCTF"]},
    "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
}, src="tests/test_toolkits_inband_recipe.py")


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.delenv("CTF_INBAND_CLI", raising=False)


def _challenge(tmp_path, capture: bytes, name="relay.pcap", extra=None) -> Path:
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "files" / name).write_bytes(capture)
    for k, v in (extra or {}).items():
        (d / "files" / k).write_bytes(v)
    return d


# ----------------------------------------------------------------------------- stub model CLI

STUB = r'''#!{python}
import json, sys
from pathlib import Path
prompt = sys.stdin.read()
here = Path(__file__).resolve().parent
(here / "prompt.json").write_text(prompt)
(here / "argv.json").write_text(json.dumps(sys.argv[1:]))
mode = (here / "mode").read_text().strip() if (here / "mode").is_file() else "ok"
if mode == "refuse":
    print(json.dumps({{"type": "result", "result": "", "stop_reason": "refusal"}}))
    sys.exit(0)
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

    def reply(decoder, *, is_protocol=True, summary="RF relay: SHA-256 keystream XOR"):
        (b.parent / "reply.json").write_text(json.dumps(
            {"is_protocol": is_protocol, "summary": summary, "decoder": decoder}))
    reply(fx.GOOD_DECODER)
    return b, reply


# ------------------------------------------------------------------- stand-in docker for sandbox.py

FAKE_DOCKER = r'''#!{python}
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
if args[0] == "image":
    print("sha256:" + "1" * 64)
    sys.exit(0)
if args[0] == "inspect":
    sys.stderr.write("Error: No such container: x\n")
    sys.exit(1)
if args[0] == "exec" and "python3" in args:
    if os.environ.get("FAKE_PYTHON_DOWN"):
        sys.stderr.write("Error response from daemon: container is not running\n")
        sys.exit(1)
    rest = args[args.index("python3") + 1:]
    host = lambda p: p.replace("/drop/", os.environ["FAKE_DROP"] + "/", 1)
    out = os.environ["FAKE_OUT"] + "/" + args[args.index("-w") + 1].split("/out/", 1)[1]
    p = subprocess.run([sys.executable] + [host(a) for a in rest], cwd=out, capture_output=True)
    sys.stdout.buffer.write(p.stdout)
    sys.stderr.buffer.write(p.stderr)
    sys.exit(p.returncode)
if args[0] == "exec" and "test" in args:
    sys.exit(1)
if args[0] == "exec":
    sys.exit(0)
sys.stderr.write("Error response from daemon: No such container: x\n")
sys.exit(1)
'''


@pytest.fixture
def stand_in_docker(tmp_path, monkeypatch):
    """tools/sandbox.py itself, driven by a stand-in docker: no daemon, no container, no image. The
    stand-in runs a `python3` exec with the call's /drop and /out mapped to the test's folders."""
    box = tmp_path / "box"
    (box / "v2" / "drop").mkdir(parents=True)
    (box / "v2" / "out").mkdir(parents=True)
    fake = tmp_path / "dockerbin" / "docker"
    fake.parent.mkdir()
    fake.write_text(FAKE_DOCKER.format(python=sys.executable))
    fake.chmod(0o755)
    log = tmp_path / "docker-calls.jsonl"
    monkeypatch.setenv("CTF_DOCKER", str(fake))
    monkeypatch.setenv("CTF_SANDBOX_DIR", str(box))
    monkeypatch.setenv("CTF_SANDBOX_NAME", f"b080-test-{os.getpid()}")
    monkeypatch.delenv("CTF_SANDBOX_IMAGE", raising=False)
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_DROP", str(box / "v2" / "drop"))
    monkeypatch.setenv("FAKE_OUT", str(box / "v2" / "out"))
    monkeypatch.delitem(sys.modules, "sandbox", raising=False)    # a fresh tools/sandbox.py, with this environment
    import sandbox
    # Wall clock: every stand-in call is an interpreter start; at a load of 100+ that can pass the 5 s
    # status-probe limit and read as "the daemon does not answer". The probe limit is not under test.
    monkeypatch.setattr(sandbox, "PROBE_TIMEOUT", 600.0)
    monkeypatch.setattr(sandbox, "SLACK", 600.0, raising=False)
    yield lambda: [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    sys.modules.pop("sandbox", None)


class FakeSandbox:
    """A stub `sandbox` module: records each run() and answers from a list of callables."""

    class SandboxDown(RuntimeError):
        pass

    class Result:
        def __init__(self, code, stdout, stderr=b""):
            self.code, self.stdout, self.stderr = code, stdout, stderr

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def run(self, tool, args, **kw):
        self.calls.append((tool, list(args), kw))
        got = self.answers[min(len(self.calls), len(self.answers)) - 1](kw)
        if isinstance(got, Exception):
            raise got
        return got


def _ok(flag, messages=("m",)):
    return lambda kw: FakeSandbox.Result(0, (json.dumps({"flag": flag, "messages": list(messages)}) + "\n").encode())


# ================================================================================== captures

def test_find_captures_goes_by_magic_not_by_name(tmp_path):
    data, _ = fx.relay_capture()
    d = _challenge(tmp_path, data, name="evidence.bin",
                   extra={"notes.pcap": b"this is not a capture, just text named like one"})
    assert [p.name for p in ir.find_captures(d)] == ["evidence.bin"]


# ================================================================================ descriptor

def test_detect_descriptor_fires_on_a_protocol_description():
    sig = ir.detect_descriptor(fx.DESCRIPTOR)
    assert sig.is_descriptor and sig.structure >= 2 and sig.layout >= 1 and sig.transform >= 1


@pytest.mark.parametrize("text", [
    fx.CHAT_TEXT,
    "GET /index.html HTTP/1.1\r\nHost: www.example.test\r\nAccept: */*\r\nUser-Agent: curl/8.0\r\n\r\n",
    "frame frame frame frames header header header " * 20,          # framing words but no byte layout
])
def test_detect_descriptor_rejects_text_that_is_not_a_spec(text):
    assert not ir.detect_descriptor(text).is_descriptor


def test_find_descriptor_reads_the_accepted_server_stream():
    data, _ = fx.relay_capture()
    tr = nf.reassemble_tcp_tolerant(data)
    desc = ir.find_descriptor([("relay.pcap", data, tr)])
    assert desc is not None and "stream 198.51.100.20:7443" in desc.source
    assert "Key = SHA-256(client_nonce || server_nonce)." in desc.text


def test_find_descriptor_falls_back_to_raw_capture_bytes():
    # no TCP stream holds it (empty reassembly), but the raw capture does (as a UDP or comment would)
    raw = b"\x00" * 40 + fx.DESCRIPTOR.encode() + b"\x00" * 40
    empty = nf.TolerantReassembly((), (), (), (), ())
    desc = ir.find_descriptor([("x.pcap", raw, empty)])
    assert desc is not None and desc.source == "x.pcap raw bytes"


# ================================================================================ model reply

def test_parse_proposal_accepts_fenced_json_and_blocks_on_bad_replies():
    good = ir.parse_proposal("```json\n" + json.dumps({"is_protocol": True, "decoder": "print(1)"}) + "\n```")
    assert isinstance(good, ir.DecoderProposal) and good.decoder == "print(1)"
    assert "not a protocol" in ir.parse_proposal(json.dumps({"is_protocol": False})).reason
    assert "no decoder" in ir.parse_proposal(json.dumps({"is_protocol": True, "decoder": "  "})).reason
    assert "not a JSON object" in ir.parse_proposal("sorry, I cannot").reason


def test_propose_decoder_sends_descriptor_streams_and_format_and_no_tools(stub_claude):
    b, _ = stub_claude
    out = ir.propose_decoder(fx.DESCRIPTOR, [{"id": "s0"}], {"regex": "CSCTF", "example": "CSCTF{...}"},
                             cli=str(b), model="haiku")
    assert isinstance(out, ir.DecoderProposal) and out.decoder == fx.GOOD_DECODER
    prompt = json.loads((b.parent / "prompt.json").read_text())
    assert prompt["descriptor"] == fx.DESCRIPTOR and prompt["streams"] == [{"id": "s0"}]
    argv = json.loads((b.parent / "argv.json").read_text())
    assert argv[argv.index("--model") + 1] == "haiku" and argv[argv.index("--tools") + 1] == ""


def test_resolve_cli_never_falls_back_from_a_named_cli(tmp_path, stub_claude):
    b, _ = stub_claude
    assert ir.resolve_cli(str(b)) == str(b)
    assert ir.resolve_cli(str(tmp_path / "missing-claude")) is None


# ============================================================================ sandboxed runs

def test_run_decoder_hands_the_sandbox_python3_with_two_inputs(monkeypatch):
    box = FakeSandbox(_ok("CSCTF{x}"))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    doc = {"descriptor": "d", "streams": []}
    run = ir.run_decoder("print('x')", doc, timeout=7, start=False)
    assert run.flag == "CSCTF{x}" and run.messages == ("m",)
    tool, args, kw = box.calls[0]
    assert tool == "python3" and args == ["{in0}", "{in1}"]
    assert kw["inputs"][0] == ("decoder.py", b"print('x')")
    assert kw["inputs"][1][0] == "streams.json" and json.loads(kw["inputs"][1][1]) == doc
    assert kw["timeout"] == 7 and kw["start"] is False
    ir.run_decoder("print('x')", doc)                              # default: the runner's own start policy
    assert "start" not in box.calls[-1][2]


def test_run_decoder_reports_a_down_sandbox_and_bad_output(monkeypatch):
    box = FakeSandbox(lambda kw: FakeSandbox.SandboxDown("not started; run tools/sandbox.py start first"))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    assert ir.run_decoder("x", {}).down.startswith("not started")
    box.answers = [lambda kw: FakeSandbox.Result(0, b"hello\n")]
    box.calls = []
    run = ir.run_decoder("x", {})
    assert run.flag is None and "not JSON" in run.parse_error and not run.down
    box.answers = [lambda kw: FakeSandbox.Result(124, b"")]
    box.calls = []
    assert ir.run_decoder("x", {}).timed_out


def test_decoder_input_scramble_changes_every_stream_byte_but_not_the_descriptor():
    data, facts = fx.relay_capture()
    tr = nf.reassemble_tcp_tolerant(data)
    streams = [(f"s{i}", s) for i, s in enumerate(tr.streams)]
    plain = ir.decoder_input("DESC", streams)
    scr = ir.decoder_input("DESC", streams, scramble=True)
    assert scr["descriptor"] == plain["descriptor"] == "DESC"
    for a, b in zip(plain["streams"], scr["streams"]):
        pa, pb = bytes.fromhex(a["data_hex"]), bytes.fromhex(b["data_hex"])
        assert len(pa) == len(pb) and all(x ^ y == ir.CONTROL_XOR for x, y in zip(pa, pb))
    assert bytes.fromhex(plain["streams"][1]["data_hex"]) == facts["server_stream"]


def test_fabricated_flag_detection():
    assert ir.fabricated("CSCTF{abcdef}", "x = 'CSCTF{abcdef}'")
    assert ir.fabricated("CSCTF{abcdef}", "x = 'CSCTF{' + 'abcdef' + '}'")
    assert not ir.fabricated("CSCTF{abcdef}", fx.GOOD_DECODER)
    assert not ir.fabricated("CSCTF{abc}", "abc = 1")                  # a short inner is too common to judge
    assert ir.fabricated("CSCTF{abc}", "print('CSCTF{abc}')")           # but the whole literal flag is caught


# ==================================================================================== solve

def test_solve_end_to_end_through_the_real_sandbox_runner(tmp_path, stub_claude, stand_in_docker):
    b, _ = stub_claude
    data, facts = fx.relay_capture()
    d = _challenge(tmp_path, data)
    res = ir.solve(d, PROFILE, cli=str(b), sandbox_start="0")
    assert res.status == "solved", res.notes
    assert list(res.flags) == [fx.FLAG]                         # the original, never the forged copy's flag
    kinds = [e.kind for e in res.evidence]
    assert "descriptor" in kinds and "decoder" in kinds and "control" in kinds
    detail = "\n".join(e.detail for e in res.evidence)
    assert f"dropped packet {facts['forged_before']} (tcp-checksum)" in detail
    assert f"conflicting copy in packet {facts['forged_valid_after']}" in detail
    assert "control run on scrambled streams did not reproduce it" in detail
    calls = stand_in_docker()
    py = [c for c in calls if c[0] == "exec" and "python3" in c]
    assert len(py) == 2                                          # the real run and the control run
    assert all(c[c.index("python3") + 1] == "-I" for c in py)   # isolated python in the container
    assert not any(c[0] in ("run", "start", "rm", "pull", "build") for c in calls)   # nothing started
    saved = tmp_path / "work" / "inband-decoders" / "chal"
    assert (saved / "decoder.py").read_text() == fx.GOOD_DECODER
    assert "conflicting copy" in (saved / "reassembly.txt").read_text()


def test_solve_a_decoder_that_prints_the_flag_whatever_it_reads_is_rejected(tmp_path, stub_claude,
                                                                            stand_in_docker):
    b, reply = stub_claude
    reply(fx.HIDDEN_DECODER)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b), sandbox_start="0")
    assert res.status == "unsure" and res.flags == ()
    assert "scrambled streams" in res.notes


def test_solve_a_flag_written_into_the_decoder_is_rejected(tmp_path, stub_claude, monkeypatch):
    b, reply = stub_claude
    reply(fx.LITERAL_DECODER)
    box = FakeSandbox(_ok(fx.FLAG))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "unsure" and "written into its own source" in res.notes
    assert len(box.calls) == 1                                   # no control run for a rejected flag


def test_solve_blocked_when_the_sandbox_is_down_and_the_decoder_never_runs_here(tmp_path, stub_claude,
                                                                                monkeypatch):
    b, reply = stub_claude
    canary = tmp_path / "ran-in-process"
    reply(f"open({str(canary)!r}, 'w').write('x')\n" + fx.GOOD_DECODER)
    monkeypatch.setenv("CTF_DOCKER", str(tmp_path / "no-docker-here"))
    monkeypatch.setenv("CTF_SANDBOX_DIR", str(tmp_path / "box"))
    monkeypatch.delitem(sys.modules, "sandbox", raising=False)
    try:
        data, _ = fx.relay_capture()
        res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    finally:
        sys.modules.pop("sandbox", None)
    assert res.status == "blocked" and "tools/sandbox.py" in res.notes and "decoder saved under" in res.notes
    assert not canary.exists()
    assert (tmp_path / "work" / "inband-decoders" / "chal" / "decoder.py").is_file()


def test_solve_control_run_down_gives_candidate_not_solved(tmp_path, stub_claude, monkeypatch):
    b, _ = stub_claude
    box = FakeSandbox(_ok(fx.FLAG), lambda kw: FakeSandbox.SandboxDown("container went away"))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "candidate" and list(res.flags) == [fx.FLAG]
    assert "not verified" in res.notes and len(box.calls) == 2


def test_solve_several_flags_is_candidate(tmp_path, stub_claude, monkeypatch):
    b, _ = stub_claude
    box = FakeSandbox(_ok(fx.FLAG, messages=["also CSCTF{second_value_here}"]), _ok(None, messages=[]))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "candidate" and set(res.flags) == {fx.FLAG, "CSCTF{second_value_here}"}


def test_solve_non_format_value_is_unsure(tmp_path, stub_claude, monkeypatch):
    b, _ = stub_claude
    monkeypatch.setitem(sys.modules, "sandbox", FakeSandbox(_ok("flag{wrong_prefix}", messages=[])))
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "unsure" and res.flags == () and "non-format" in res.notes


def test_solve_decoder_timeout_is_unsure(tmp_path, stub_claude, monkeypatch):
    b, _ = stub_claude
    monkeypatch.setitem(sys.modules, "sandbox", FakeSandbox(lambda kw: FakeSandbox.Result(124, b"")))
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b), run_timeout="3")
    assert res.status == "unsure" and "timed out" in res.notes


def test_solve_none_without_capture(tmp_path):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "files" / "readme.txt").write_text(fx.DESCRIPTOR)
    res = ir.solve(d, PROFILE, cli="/nonexistent/claude")
    assert res.status == "none" and "no pcap" in res.notes


def test_solve_none_without_descriptor_still_reports_the_reassembly(tmp_path):
    frames = [fx.tcp_frame(fx.CLIENT, fx.SERVER, 40000, 80, 1000, 0x02),
              fx.tcp_frame(fx.CLIENT, fx.SERVER, 40000, 80, 1001, 0x18, b"X" * 8, bad_tcp=True),
              fx.tcp_frame(fx.CLIENT, fx.SERVER, 40000, 80, 1001, 0x18, fx.CHAT_TEXT.encode())]
    res = ir.solve(_challenge(tmp_path, fx.pcap(frames)), PROFILE, cli="/nonexistent/claude")
    assert res.status == "none" and "no in-band protocol descriptor" in res.notes
    assert "1 dropped" in res.notes
    assert any("dropped packet 1 (tcp-checksum)" in e.detail for e in res.evidence)


def test_solve_unsure_when_no_capture_is_admitted(tmp_path):
    bad = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60                      # pcap magic, broken container
    res = ir.solve(_challenge(tmp_path, bad), PROFILE, cli="/nonexistent/claude")
    assert res.status == "unsure" and "not admitted" in res.notes


def test_solve_blocked_without_cli(tmp_path):
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(tmp_path / "missing-claude"))
    assert res.status == "blocked" and "Claude CLI" in res.notes


@pytest.mark.parametrize("mode,word", [("refuse", "declined"), ("garbage", "no JSON")])
def test_solve_blocked_on_a_model_error(tmp_path, stub_claude, mode, word):
    b, _ = stub_claude
    (b.parent / "mode").write_text(mode)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "blocked" and word in res.notes


def test_solve_model_sees_only_the_accepted_stream_bytes(tmp_path, stub_claude, monkeypatch):
    b, _ = stub_claude
    monkeypatch.setitem(sys.modules, "sandbox", FakeSandbox(_ok(None, messages=[])))
    data, facts = fx.relay_capture()
    ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    prompt = json.loads((b.parent / "prompt.json").read_text())
    srv = [s for s in prompt["streams"] if s["src"].endswith(":7443")][0]
    assert srv["length"] == len(facts["server_stream"])
    assert prompt["flag_format"]["regex"] and "CSCTF" in prompt["flag_format"]["regex"]
    assert "END-SPEC" in prompt["descriptor"]


# ======================================================================= verification round 1

def test_detect_descriptor_requires_a_byte_layout_even_at_a_passing_score():
    # many distinct framing and transform words, no byte-layout phrase: the score alone would pass
    text = ("Each frame has a header with a magic, an opcode, a version field and a payload. The "
            "payload is xor with a keystream from the nonce and key, then an hmac checksum.")
    sig = ir.detect_descriptor(text)
    assert sig.layout == 0 and sig.structure >= 2 and sig.score >= 7
    assert not sig.is_descriptor
    with_layout = ir.detect_descriptor(text + " The length is a big-endian uint16.")
    assert with_layout.layout >= 1 and with_layout.is_descriptor


def _stream(data: bytes, sport: int) -> nf.TCPStream:
    return nf.TCPStream(fx.SERVER, sport, fx.CLIENT, fx.CPORT, 0, 1, data, True, True, True, 2, 0, None, None)


def test_find_descriptor_keeps_the_first_of_equal_scoring_streams():
    one = nf.TolerantReassembly((_stream(fx.DESCRIPTOR.encode(), 7001), _stream(fx.DESCRIPTOR.encode(), 7002)),
                                (), (), (), ())
    desc = ir.find_descriptor([("a.pcap", b"", one)])
    assert desc.source == f"a.pcap stream {fx.SERVER}:7001 -> {fx.CLIENT}:{fx.CPORT}"
    tr = nf.TolerantReassembly((_stream(fx.DESCRIPTOR.encode(), 7001),), (), (), (), ())
    assert ir.find_descriptor([("a.pcap", b"", tr), ("b.pcap", b"", tr)]).source.startswith("a.pcap ")


def test_find_descriptor_keeps_the_first_of_equal_scoring_raw_captures():
    raw = b"\x00" * 8 + fx.DESCRIPTOR.encode()
    empty = nf.TolerantReassembly((), (), (), (), ())
    assert ir.find_descriptor([("a.pcap", raw, empty), ("b.pcap", raw, empty)]).source == "a.pcap raw bytes"


def test_decoder_input_caps_the_stream_bytes_handed_to_the_decoder(monkeypatch):
    monkeypatch.setattr(ir, "MAX_DECODER_STREAM_BYTES", 10)
    streams = [("s0", _stream(b"abcdefgh", 7001)), ("s1", _stream(b"ijklmnop", 7002)),
               ("s2", _stream(b"qrst", 7003))]
    doc = ir.decoder_input("D", streams)
    assert [bytes.fromhex(s["data_hex"]) for s in doc["streams"]] == [b"abcdefgh", b"ij", b""]
    scr = ir.decoder_input("D", streams, scramble=True)
    assert [len(bytes.fromhex(s["data_hex"])) for s in scr["streams"]] == [8, 2, 0]


def test_solve_control_run_timeout_gives_candidate_not_solved(tmp_path, stub_claude, monkeypatch):
    # a decoder that hangs only on scrambled input proves nothing about where its flag came from
    b, _ = stub_claude
    box = FakeSandbox(_ok(fx.FLAG), lambda kw: FakeSandbox.Result(124, b""))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    data, _ = fx.relay_capture()
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b))
    assert res.status == "candidate" and list(res.flags) == [fx.FLAG]
    assert "timed out" in res.notes and "not verified" in res.notes and len(box.calls) == 2


@pytest.mark.parametrize("opt, want", [("0", False), ("false", False), ("off", False), (None, None)])
def test_solve_passes_the_sandbox_start_knob_to_both_runs(tmp_path, stub_claude, monkeypatch, opt, want):
    # sandbox_start=0 must reach the sandbox runner on the real run AND the control run as start=False
    # (never start a container); without the option the runner keeps its own start policy (no kwarg).
    b, _ = stub_claude
    box = FakeSandbox(_ok(fx.FLAG), _ok(None, messages=[]))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    data, _ = fx.relay_capture()
    extra = {} if opt is None else {"sandbox_start": opt}
    res = ir.solve(_challenge(tmp_path, data), PROFILE, cli=str(b), **extra)
    assert res.status == "solved", res.notes
    assert len(box.calls) == 2
    for _tool, _args, kw in box.calls:
        if want is None:
            assert "start" not in kw
        else:
            assert kw["start"] is want
