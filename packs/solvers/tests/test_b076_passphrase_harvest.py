"""B-076: solvers/toolkits/passphrase_harvest.py -- quoted strings of a cover's sibling notes, B-074's tokens
after them, the steghide tries through stego_tools.steghide_extract, the CLI and its [intake] table, and the
whole Xenoglossophobia-shaped chain: socat log -> sweep -> XMODEM JPEG beside the Latin note -> passphrase.

Nothing here touches Docker: stego_tools' sandbox is replaced by a stand-in that plays steghide's side
(it opens the cover only under the one passphrase it was given). A real steghide run is a human step.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import archive_expand
import b076_fixtures as fx
import passphrase_harvest as ph
import stego_tools
from ctf import event, sweep
from ctf.engines import manifest as M
from ctf.intake import engines as E
from ctf.intake.guard import Guard

REPO = Path(__file__).resolve().parent.parent
SPOOKY = event.load("spooky")
LATIN = ('Ut clavem invenias ad plura de "loco" cognoscenda, intellegere debes quid imago tibi significet.\n'
         'Est id quod "supermercado" vocant!\n')
PAYLOAD = b"\\x4d\\x65\\x75 ... O bandeira e spooky{many_quoted_words}\n"
MANIFEST = REPO / "solvers" / "toolkits" / "passphrase_harvest.manifest.toml"


def test_quoted_reads_every_quote_style_in_order_and_never_an_apostrophe():
    text = ("He said \"alpha\" then “beta gamma”, « delta » and `eps`; it's Bob's 'zeta' "
            "‘eta’ „theta“ \"go!\"")
    assert ph.quoted(text) == ["alpha", "beta gamma", "delta", "eps", "zeta", "eta", "theta", "go!", "go"]
    assert ph.quoted("don't won't can't") == []
    assert ph.quoted('"" "..." "' + "x" * 80 + '"') == []           # empty, punctuation only, too long


def _scene(tmp_path, note=LATIN, extra_files=()):
    d = tmp_path / "cover"
    d.mkdir()
    (d / "image.jpg").write_bytes(fx.fake_jpeg(200))
    (d / "note.txt").write_text(note)
    (d / ".sweep.json").write_text('{"x": "\\"sweepword\\""}')
    (d / "blob.bin").write_bytes(b"\x00\x01\"binaryword\"")
    for name, data in extra_files:
        (d / name).write_bytes(data)
    return d / "image.jpg"


def test_sibling_texts_skip_the_cover_hidden_and_binary_files(tmp_path):
    cover = _scene(tmp_path, extra_files=[("wide.txt", '"widepass"'.encode("utf-16"))])
    names = [n for n, _ in ph.sibling_texts(cover)]
    assert names == ["note.txt", "wide.txt"]
    assert dict(ph.sibling_texts(cover))["wide.txt"] == '"widepass"'


def test_candidates_put_quoted_strings_first_then_b074_tokens(tmp_path):
    cover = _scene(tmp_path)
    cands = ph.candidates(cover, extra=['the brief says "brief-word"'])
    values = [c.value for c in cands]
    assert values[:3] == ["loco", "supermercado", "brief-word"]
    assert cands[0].source == "quoted in note.txt" and cands[2].source == "quoted in extra text 1"
    assert "cognoscenda," in values and values.index("cognoscenda,") > 2      # a B-074 sibling token, after
    assert all(c.source == "sibling token (B-074 harvest)" for c in cands[3:])
    assert "sweepword" not in values and "binaryword" not in values
    quoted_only = ph.candidates(cover, tokens=False)
    assert [c.value for c in quoted_only] == ["loco", "supermercado"]


class FakeSandbox:
    """What stego_tools imports as `sandbox`: steghide's side for one passphrase, every call recorded."""

    class SandboxDown(RuntimeError):
        pass

    class Lit(str):
        pass

    class Result:
        def __init__(self, code, stdout=b"", stderr=b"", files=None):
            self.code, self.stdout, self.stderr, self.files, self.note = code, stdout, stderr, files or {}, ""

        @property
        def timed_out(self):
            return self.code == 124

    def __init__(self, passphrase, payload, down=False):
        self.passphrase, self.payload, self.down, self.calls = passphrase, payload, down, []
        self.starts = []

    def run(self, tool, args, inputs=(), timeout=60, start=True):
        # `start` mirrors tools/sandbox.run (B-182: stego_tools passes start=False inside no_start())
        self.calls.append((tool, list(args), [n for n, _ in inputs]))
        self.starts.append(start)
        if self.down:
            raise self.SandboxDown("docker: Cannot connect to the Docker daemon")
        pw = args[args.index("-p") + 1]
        assert isinstance(pw, self.Lit)                 # the passphrase reaches steghide as written
        if tool == "steghide" and pw == self.passphrase:
            return self.Result(0, b"", b"wrote extracted data to \"payload\".", {"payload": self.payload})
        return self.Result(1, b"", b"steghide: could not extract any data with that passphrase!")


@pytest.fixture
def sandbox(monkeypatch):
    holder = {}

    def use(passphrase="supermercado", payload=PAYLOAD, down=False):
        holder["sb"] = FakeSandbox(passphrase, payload, down)
        monkeypatch.setattr(stego_tools, "_sandbox", lambda: holder["sb"])
        return holder["sb"]
    return use


def test_try_steghide_walks_the_candidates_through_steghide_extract(tmp_path, sandbox):
    sb = sandbox()
    cover = _scene(tmp_path)
    att = ph.try_steghide(cover.read_bytes(), ph.candidates(cover))
    assert att.found.value == "supermercado" and att.payload == PAYLOAD and att.tried == 2
    assert [c[1][c[1].index("-p") + 1] for c in sb.calls] == ["loco", "supermercado"]
    assert all(c[0] == "steghide" and c[1][0] == "extract" for c in sb.calls)
    assert sb.starts == [True, True]                     # outside stego_tools.no_start() a call may start one


def test_try_steghide_stops_when_the_sandbox_is_down(tmp_path, sandbox):
    sb = sandbox(down=True)
    cover = _scene(tmp_path)
    att = ph.try_steghide(cover.read_bytes(), ph.candidates(cover))
    assert att.found is None and att.tried == 1 and "sandbox down" in att.blocked
    assert len(sb.calls) == 1


def test_try_steghide_respects_its_limit_and_says_what_was_left(tmp_path, sandbox):
    sandbox(passphrase="never")
    cover = _scene(tmp_path)
    cands = ph.candidates(cover)
    att = ph.try_steghide(cover.read_bytes(), cands, limit=3)
    assert att.found is None and att.tried == 3 and not att.blocked
    assert att.notes == [f"{len(cands) - 3} candidate(s) past the limit of 3 not tried"]


def test_try_steghide_takes_an_unreadable_cover_as_blocked(tmp_path):
    class R:
        ok, data, code = False, None, 1
        note = "steghide: the cover was not read whole (Premature end of JPEG file): no reading of the passphrase"
    att = ph.try_steghide(b"x", [ph.Candidate("a", "s"), ph.Candidate("b", "s")], extract=lambda d, p: R())
    assert att.tried == 1 and "no reading of the passphrase" in att.blocked


def _cli(path: Path, *args):
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env["CTF_EVENT"] = "spooky"
    return subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "passphrase_harvest.py"), *args, str(path)],
                          capture_output=True, text=True, env=env, cwd=str(path.parent), timeout=300)


def test_cli_lists_quoted_candidates_as_unsure_and_names_the_step(tmp_path):
    cover = _scene(tmp_path)
    out = _cli(cover)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().splitlines()
    assert "candidate = 'loco' (quoted in note.txt)" in lines
    assert "candidate = 'supermercado' (quoted in note.txt)" in lines
    assert "next = python solvers/toolkits/passphrase_harvest.py --steghide image.jpg" in lines
    res = json.loads(lines[-1])
    assert res["status"] == "unsure" and "2 quoted" in res["notes"]


def test_cli_with_no_quoted_string_is_none(tmp_path):
    cover = _scene(tmp_path, note="nothing quoted in this note at all\n")
    res = json.loads(_cli(cover).stdout.strip().splitlines()[-1])
    assert res["status"] == "none"


def test_cli_steghide_with_the_sandbox_unreachable_is_blocked_never_none(tmp_path):
    cover = _scene(tmp_path)
    # a sandbox that is down in the child process: tools/sandbox.py names the reason; the CLI must say
    # blocked, not "none of the candidates opened it". The docker CLI is a stand-in ($CTF_DOCKER, the
    # sandbox's own test hook) whose daemon never answers, so no container is ever reached or started.
    stand_in = tmp_path / "docker-down"
    stand_in.write_text("#!/bin/sh\necho 'Cannot connect to the Docker daemon at unix:///absent.sock' >&2\nexit 1\n")
    stand_in.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env.update(CTF_EVENT="spooky", CTF_DOCKER=str(stand_in), CTF_SANDBOX_NAME="b076-test-absent")
    out = subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "passphrase_harvest.py"), "--steghide",
                          "--max", "2", str(cover)], capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=300)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res["status"] == "blocked", out.stdout


def test_intake_plans_the_harvest_on_a_cover_in_the_scratch_copy(tmp_path):
    cover = _scene(tmp_path)
    m = M.load(MANIFEST)
    plan = E.plan([m], "stego", "", cover.parent, guard=Guard(mode="hook", reason="test"))
    assert [j.files[0].name for j in plan.jobs if j.engine == m.id] == ["image.jpg"]
    assert list(m.intake.args) == ["{file}"] and not m.intake.spawns


def test_the_serial_onion_chain_reaches_the_passphrase_and_the_payload_flag(tmp_path, monkeypatch, sandbox):
    """socat log -> the sweep's XMODEM members (a JPEG beside the Latin note) -> the quoted passphrase ->
    steghide_extract (stand-in) -> the flag in the payload."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [])
    log = fx.SocatLog()
    fx.xmodem_send(log, fx.fake_jpeg(400), eot_ack=False)    # the evidence's shape: the first EOT is never ACKed,
    fx.xmodem_send(log, LATIN.encode())                      # a fresh NAK restarts the sender at block 1
    ch = tmp_path / "wd" / "9-xeno"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": 9, "name": "xeno", "category": "Scripting", "description": ""}))
    (ch / "files" / "serial-capture.log").write_text(log.text())
    rep = sweep.sweep(ch, SPOOKY)
    cover = ch / "unpacked" / "serial-capture.log.unpacked" / "socat" / "xmodem-1.jpg"
    assert cover.is_file() and (cover.parent / "xmodem-2.txt").read_text() == LATIN
    assert rep.result.status == "none"                       # the flag is behind steghide: the sweep cannot reach it
    sandbox()
    att = ph.try_steghide(cover.read_bytes(), ph.candidates(cover))
    assert att.found.value == "supermercado" and att.found.source == "quoted in xmodem-2.txt"
    assert b"spooky{many_quoted_words}" in att.payload


# ---------------------------------------------------------------- the payload's last layer


def _mixed(head: str, tail: bytes) -> bytes:
    """The Xenoglossophobia payload shape: `\\xHH` escapes of Latin-1 text, then space-separated decimals."""
    return b"".join(b"\\x%02x" % c for c in head.encode("latin-1")) + b" " + b" ".join(b"%d" % c for c in tail)


MIXED = _mixed("Olá amigo! A bandeira é spooky{synthetic_mi", b"x3d_l@yers}")


def test_numeric_escapes_decode_hex_escapes_and_decimals_together():
    assert ph.numeric_escapes(MIXED) == "Olá amigo! A bandeira é spooky{synthetic_mi".encode("latin-1") + b"x3d_l@yers}"
    assert ph.numeric_escapes(b"0x41, 0x42 \\103 68") == b"ABCD"            # 0x, octal escape, decimal
    assert ph.numeric_escapes(b"\\x41\\x42 hello 67") is None                # a word is not a byte value
    assert ph.numeric_escapes(b"65 66 67 300") is None                       # past 255
    assert ph.numeric_escapes(b"65 66 67") is None                           # fewer than MIN_ESCAPES values
    assert ph.numeric_escapes(b"\\x41\\x42\\x43\\x44") == b"ABCD"
    assert ph.numeric_escapes(b"65 66 67 68 trailing") is None               # a non-numeric tail
    assert ph.numeric_escapes(b"\\x41\\x42\\x43\\x44 trailing") is None      # same after hex escapes
    assert ph.numeric_escapes(b"lead 65 66 67 68") is None                   # and a lead-in


def test_numeric_escape_run_decodes_the_longest_run_inside_prose():
    assert ph.numeric_escape_run(b"flag: \\x41\\x42\\x43\\x44 ok") == b"ABCD"
    assert ph.numeric_escape_run(MIXED) == ph.numeric_escapes(MIXED)          # a whole-text run too
    # the longer of two runs wins, whichever comes first
    assert ph.numeric_escape_run(b"a 65 66 67 68 b \\x61\\x62\\x63\\x64\\x65 c") == b"abcde"
    assert ph.numeric_escape_run(b"a \\x61\\x62\\x63\\x64\\x65 b 65 66 67 68 c") == b"abcde"
    assert ph.numeric_escape_run(b"x 65 66 67 68 y 97 98 99 100") == b"ABCD"  # a tie keeps the earliest
    assert ph.numeric_escape_run(b"in 2024 we had 3 cats and 4 dogs") is None  # short runs, a 4-digit number
    assert ph.numeric_escape_run(b"see 65 66 67 300 here") is None            # a run past 255
    assert ph.numeric_escape_run(b"no numbers at all") is None


def test_payload_flags_reads_the_mixed_escape_layer_and_the_codec_graph():
    profile = event.load("spooky")
    assert ph.payload_flags(MIXED, profile) == (["spooky{synthetic_mix3d_l@yers}"], "numeric escapes decoded")
    assert ph.payload_flags(b"plain spooky{as_written}\n", profile) == (["spooky{as_written}"], "as written")
    b64 = __import__("base64").b64encode(b"inner spooky{base64_payload_layer}").decode().encode()
    flags, how = ph.payload_flags(b64, profile)
    assert flags == ["spooky{base64_payload_layer}"] and how == "codec graph"
    assert ph.payload_flags(b"\x00\x01 nothing here", profile) == ([], "")
    lead = b"A nota diz: " + MIXED + b" -- fim"
    assert ph.payload_flags(lead, profile) == (["spooky{synthetic_mix3d_l@yers}"], "numeric escape run decoded")
    inner = __import__("base64").b64encode(b"spooky{run_then_codec}")
    run_b64 = b"note: " + b" ".join(b"%d" % c for c in inner) + b" end"
    assert ph.payload_flags(run_b64, profile) == (["spooky{run_then_codec}"], "numeric escape run, then the codec graph")


def test_cli_steghide_decodes_the_mixed_payload_to_the_flag(tmp_path, sandbox, monkeypatch, capsys):
    monkeypatch.setenv("CTF_EVENT", "spooky")
    sandbox(payload=MIXED)
    cover = _scene(tmp_path)
    assert ph.main(["--steghide", "--no-tokens", str(cover)]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert "decoded = numeric escapes decoded" in lines
    res = json.loads(lines[-1])
    assert res["status"] == "solved" and res["flags"] == ["spooky{synthetic_mix3d_l@yers}"]


def test_the_harvest_rules_come_from_b074_by_their_public_names(tmp_path):
    hv = ph._harvest()
    assert hv.SKIP_SIBLING.match("_passwords.json") and hv.valid("pw") and not hv.valid("a\nb")
    cover = _scene(tmp_path, extra_files=[("_passwords.json", b'the store says "storeword"\n'),
                                          ("clue.txt", b'the note says "noteword"\n')])
    assert [n for n, _ in ph.sibling_texts(cover)] == ["clue.txt", "note.txt"]   # the store is never read
    values = [c.value for c in ph.candidates(cover, tokens=False)]
    assert "noteword" in values and "storeword" not in values
