"""B-208: the text-trick pass wired into ctf.fastlane (try_solve, the rules-page sanity path, the B-041
welcome auto-trigger and the intake decode blobs) and the ``ctf text-tricks`` CLI.

All briefs and rules pages are SYNTHETIC; fetches are injected fakes (no network) and nothing submits.

Run:  .venv/bin/python -m pytest tests/test_fastlane_texttricks.py
"""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from ctf import cli, event, fastlane
from ctf import intake as I

FLAG = "CSCTF{h1dden_1n_the_rules}"
CFG = SimpleNamespace(base_url="https://board.example.test", user_agent="test")


def _bits(msg: str) -> str:
    return "".join(format(b, "08b") for b in msg.encode())


def _bullets(letters: str) -> str:
    words = {"{": "{ braces open", "}": "} braces close", "_": "_ underscores count"}
    return "\n".join("- " + words.get(c, f"{c}ule number about the event") for c in letters)


def _trailing_ws(msg: str) -> str:
    return "\n".join(f"line {i}" + (" " if b == "0" else "\t") for i, b in enumerate(_bits(msg)))


def _no_fetch(url):
    raise AssertionError(f"no network expected, got {url}")


# -------------------------------------------------------------------------------------------------
# try_solve / try_text_tricks
# -------------------------------------------------------------------------------------------------
def test_try_solve_returns_a_flag_an_acrostic_spells_in_an_ordinary_brief():
    detail = {"name": "Notice Board", "category": "misc", "description": "Notes:\n" + _bullets(FLAG)}
    r = fastlane.try_solve(detail, None, cfg=CFG, fetch=_no_fetch, online=False)
    assert r is not None and r["klass"] == "text-trick"
    assert r["flag"] == FLAG and r["confidence"] == "high" and r["source"] == "description"
    assert "bullet-initials" in r["how"]
    assert r["text_tricks"]["description"]["flag"] == FLAG


def test_try_solve_leaves_a_brief_full_of_brand_names_alone():
    # camel-case brands give chance mid-word capitals ("picoCTF" -> CTF...): no candidate, no clue
    for desc in ("Like picoCTF, HackTheBox and TryHackMe, this event is for beginners.",
                 "Use JavaScript on GitHub with PowerShell to parse the log."):
        detail = {"name": "Log Parse", "category": "misc", "description": desc}
        assert fastlane.try_solve(detail, None, cfg=CFG, fetch=_no_fetch, online=False) is None, desc


def test_try_solve_reads_a_sanity_brief_once(monkeypatch):
    # try_sanity already read the brief of a sanity challenge; step 1b must not read it again
    desc = _trailing_ws("hello world")
    real, seen = fastlane._tt.scan, []

    def counting_scan(text, **kw):
        seen.append(text)
        return real(text, **kw)

    monkeypatch.setattr(fastlane._tt, "scan", counting_scan)
    detail = {"name": "Read the Rules", "category": "sanity", "description": desc}
    r = fastlane.try_solve(detail, None, cfg=CFG, fetch=_no_fetch, online=False)
    assert r["klass"] == "sanity" and r["candidate"] == "hello world"
    assert seen.count(desc) == 1


def test_try_solve_leaves_an_ordinary_brief_alone():
    detail = {"name": "Heap Overflow", "category": "pwn",
              "description": "Connect to the service.\nPop a shell.\nRead the flag file.\nGood luck."}
    assert fastlane.try_solve(detail, None, cfg=CFG, fetch=_no_fetch, online=False) is None


def test_a_plain_acrostic_is_shown_only_when_the_brief_hints_at_a_text_trick():
    lines = "Read me\nEvery line\nAlways counts\nDo it"
    plain = {"name": "Poem", "category": "misc", "description": lines}
    assert fastlane.try_text_tricks(plain) is None
    hinted = {"name": "Poem", "category": "misc", "description": "Take the first letter.\n" + lines}
    assert fastlane._hints_text_trick(hinted)
    r = fastlane.try_solve(hinted, None, cfg=CFG, fetch=_no_fetch, online=False)
    assert r is not None and r["klass"] == "text-trick" and r["flag"] is None
    assert "TREAD" in r["instruction"] and r["confidence"] == "low"


def test_a_prefix_led_reading_is_a_candidate_never_a_flag():
    detail = {"name": "Hashphobia", "category": "misc",
              "description": "\n".join(["Cold", "Sharp", "Crisp", "Thin", "Fresh", "Salty", "Airy", "Yellow"])}
    r = fastlane.try_solve(detail, None, cfg=CFG, fetch=_no_fetch, online=False)
    assert r["flag"] is None and r["candidate"] == "CSCTF{SAY}"
    assert r["instruction"].startswith("verify by hand") and r["confidence"] == "medium"


def test_several_hidden_flags_are_ambiguous_and_none_is_returned():
    zw = "".join("​" if b == "0" else "‌" for b in _bits("CSCTF{other}"))
    detail = {"name": "Two", "category": "misc", "description": _bullets(FLAG) + "\n" + zw}
    r = fastlane.try_text_tricks(detail)
    assert r["flag"] is None and "ambiguous" in r["how"]
    assert {c["value"] for c in r["candidates"]} >= {FLAG, "CSCTF{other}"}


# -------------------------------------------------------------------------------------------------
# sanity: the brief and the fetched rules page
# -------------------------------------------------------------------------------------------------
def test_sanity_reads_the_rules_page_bullets_when_no_flag_is_printed():
    items = "".join(f"<li>{line[2:]}</li>" for line in _bullets(FLAG).split("\n"))
    page = f"<html><body><h1>Rules</h1><p>There is a flag here.</p><ul>{items}</ul></body></html>"
    seen = []

    def fetch(url):
        seen.append(url)
        return page if url.endswith("/rules") else "<html><body><p>home</p></body></html>"

    detail = {"name": "Sanity Check 2", "category": "sanity", "description": "Read the rules."}
    r = fastlane.try_sanity(detail, CFG, fetch, online=True)
    assert r["flag"] == FLAG and r["klass"] == "text-trick"
    assert r["source"] == "https://board.example.test/rules"
    assert seen == [CFG.base_url + p for p in fastlane._RULES_PATHS]        # all pages read, then the pass


def test_sanity_brief_acrostic_is_found_offline():
    detail = {"name": "Read the Rules", "category": "sanity", "description": _bullets(FLAG)}
    r = fastlane.try_sanity(detail, CFG, _no_fetch, online=False)
    assert r["flag"] == FLAG and r["klass"] == "text-trick"


def test_sanity_offline_without_a_hidden_flag_carries_the_reading_in_its_instruction():
    detail = {"name": "Read the Rules", "category": "sanity", "description": _trailing_ws("hello world")}
    r = fastlane.try_sanity(detail, CFG, _no_fetch, online=False)
    assert r["klass"] == "sanity" and r["flag"] is None
    assert r["candidate"] == "hello world"
    assert "rules page" in r["instruction"] and "text tricks:" in r["instruction"]
    assert r["text_tricks"]["description"]["candidates"]


def test_a_printed_rules_page_flag_still_wins_over_the_text_pass():
    printed = "CSCTF{printed_on_page}"
    page = f"<html><body><p>{printed}</p><ul>" + "".join(
        f"<li>{ln[2:]}</li>" for ln in _bullets(FLAG).split("\n")) + "</ul></body></html>"
    detail = {"name": "Read the Rules", "category": "sanity", "description": "Rules."}
    r = fastlane.try_sanity(detail, CFG, lambda url: page, online=True)
    assert r["flag"] == printed and r["klass"] == "sanity"


# -------------------------------------------------------------------------------------------------
# B-041 welcome trigger and intake
# -------------------------------------------------------------------------------------------------
def test_try_welcome_recovers_a_hidden_brief_flag():
    detail = {"name": "Welcome Aboard", "category": "misc", "description": "Hello!\n" + _bullets(FLAG)}
    r = fastlane.try_welcome(detail, None)
    assert r["flag"] == FLAG and r["klass"] == "welcome" and "welcome auto-trigger" in r["how"]


def test_try_welcome_without_a_hidden_flag_keeps_its_human_step_and_adds_the_reading():
    detail = {"name": "Welcome Aboard", "category": "misc", "description": _trailing_ws("say hi")}
    r = fastlane.try_welcome(detail, None, base_url="https://board.example.test")
    assert r["flag"] is None and r["candidate"] == "say hi"
    assert "board.example.test" in r["instruction"] and "text tricks:" in r["instruction"]


class _Adapter:
    kind = "fake"

    def __init__(self, ch):
        self.ch = ch

    def list_challenges(self):
        return [self.ch]

    def get_challenge(self, cid):
        return self.ch

    def download_files(self, cid, dest):
        return []

    def submit(self, cid, flag):
        raise AssertionError("intake must never submit")


def _intake(tmp_path, name, category, description):
    from ctf.platform.base import Challenge
    ch = Challenge(id="5", name=name, category=category, points=10, description=description,
                   files=(), solved_by_team=False)
    return I.intake_one("5", event.load("csctf"), adapter=_Adapter(ch), workdir=tmp_path / "wd",
                        options=I.Options(engines=False, net_guard="hook"), manifests=[])


def test_intake_solves_a_welcome_challenge_whose_brief_hides_the_flag(tmp_path):
    rep = _intake(tmp_path, "Welcome Aboard", "misc", "Hi!\n" + _bullets(FLAG))
    assert rep.status == "solved", (rep.status, rep.notes)
    assert rep.result.flags == (FLAG,)


def test_whitespace_hidden_base64_reaches_the_intake_decode_stage(tmp_path):
    assert fastlane._crib is not None           # the carried decoder is in-tree; its absence is a failure
    hidden = base64.b64encode(b"CSCTF{ws_b64_layer}").decode()
    blobs = fastlane._encoded_blobs_from_desc("A quiet brief.\n" + _trailing_ws(hidden))
    assert hidden.encode() in blobs
    rep = _intake(tmp_path, "Quiet Brief", "misc", "A quiet brief.\n" + _trailing_ws(hidden))
    assert "CSCTF{ws_b64_layer}" in rep.result.flags, (rep.status, rep.notes)


def test_encoded_blobs_skip_acrostics_without_braces():
    blobs = fastlane._encoded_blobs_from_desc("Alpha\nBravo\nCharlie\nDelta")
    assert blobs == [b"Alpha\nBravo\nCharlie\nDelta"]
    # an acrostic needs BOTH braces: an opening or a closing one alone is not a flag-shaped reading
    for half in ("ab{cd", "abcd}"):
        desc = _bullets(half)
        assert fastlane._encoded_blobs_from_desc(desc) == [desc.encode()], half
    with_braces = fastlane._encoded_blobs_from_desc(_bullets("ab{cd}"))
    assert b"ab{cd}" in with_braces


# -------------------------------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------------------------------
def test_cli_reads_a_file_and_exits_zero_on_one_flag(tmp_path, capsys):
    f = tmp_path / "rules.txt"
    f.write_text(_bullets(FLAG))
    assert cli.main(["text-tricks", str(f), "--event", "csctf"]) == 0
    out = capsys.readouterr().out
    assert f"FLAG {FLAG}" in out and "bullet-initials" in out


def test_cli_json_and_exit_one_with_candidates_only(capsys):
    assert cli.main(["text-tricks", "--text", _trailing_ws("hello world"), "--json", "--event", "csctf"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["flag"] is None and data[0]["candidates"][0]["value"] == "hello world"


def test_cli_refuses_an_oversized_file_or_stdin(tmp_path, capsys, monkeypatch):
    import io

    from ctf.cli import text_tricks
    big = tmp_path / "corpus.txt"
    big.write_bytes(b"x" * (text_tricks.MAX_TEXT + 1))
    assert cli.main(["text-tricks", str(big), "--event", "csctf"]) == 2
    assert "over" in capsys.readouterr().err
    monkeypatch.setattr("sys.stdin", io.StringIO("y" * (text_tricks.MAX_TEXT + 1)))
    assert cli.main(["text-tricks", "-", "--event", "csctf"]) == 2
    assert "stdin: over" in capsys.readouterr().err
    # exactly MAX_TEXT is read (and gives no flag: exit 1, not 2)
    edge = tmp_path / "edge.txt"
    edge.write_bytes(b"x" * text_tricks.MAX_TEXT)
    assert cli.main(["text-tricks", str(edge), "--event", "csctf"]) == 1


def test_cli_exits_two_with_nothing_to_read_or_a_missing_file(tmp_path, capsys):
    assert cli.main(["text-tricks", "--event", "csctf"]) == 2
    assert cli.main(["text-tricks", str(tmp_path / "absent.txt"), "--event", "csctf"]) == 2
    assert cli.main(["text-tricks", "--text", "x", "--event", "no-such-event-b208"]) == 2
    err = capsys.readouterr().err
    assert "nothing to read" in err and "not a file" in err and "EventError" in err
